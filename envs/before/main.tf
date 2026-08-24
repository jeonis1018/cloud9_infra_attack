# ==============================================
# provider 설정
# ==============================================

terraform {
  required_version = ">= 1.5.0"

  backend "s3" {
      bucket = "cloud943-attack-tfstate"
      key    = "envs/before/terraform.tfstate"
      region = "ap-northeast-2"
  }
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">=3.5"
    }
  }
}

provider "aws" {
  region  = "ap-northeast-2"
  profile = var.aws_profile
}

# ==============================================
# vpc 블록
# ==============================================

module "vpc" {
  source = "../../modules/vpc"

  vpc_name             = "WHS_VPC"
  vpc_cidr             = "10.3.0.0/16"
  availability_zones   = ["ap-northeast-2a", "ap-northeast-2b"]
  public_subnet_cidrs  = ["10.3.1.0/24", "10.3.2.0/24"]
  private_subnet_cidrs = ["10.3.11.0/24", "10.3.12.0/24"]
}

# ==============================================
# alb_waf 블록
# ==============================================

module "alb_waf" {
  source = "../../modules/alb-waf"

  vpc_id            = module.vpc.vpc_id
  vpc_name          = "WHS_VPC"
  public_subnet_ids = module.vpc.public_subnet_ids

  certificate_arn = "arn:aws:acm:ap-northeast-2:896986966760:certificate/e022050c-8d53-4fa5-b642-8698aef04f3f"
}

# ==============================================
# s3_endpoint 블록
# ==============================================

module "s3_endpoint" {
  source = "../../modules/s3-endpoint"

  vpc_id                  = module.vpc.vpc_id
  private_route_table_ids = module.vpc.private_route_table_ids
  bucket_name_prefix      = "cloud9-attack-target"

  allowed_vpc_endpoint_only = var.allowed_vpc_endpoint_only
}

# ==============================================
# iam 블록
# ==============================================

module "iam" {
  source = "../../modules/iam"

  s3_bucket_arn = module.s3_endpoint.bucket_arn

  enable_least_privilege = var.enable_least_privilege
}

# ==============================================
# ec2 블록
# ==============================================

module "ec2" {
  source = "../../modules/ec2"

  vpc_id                = module.vpc.vpc_id
  private_subnet_ids    = module.vpc.private_subnet_ids
  instance_profile_name = module.iam.ec2_instance_profile_name
  alb_security_group_id = module.alb_waf.alb_security_group_id

  enable_imdsv2  = var.enable_imdsv2
  instance_type  = "t3.micro"
  instance_count = 2
  app_port       = 8080

  user_data = templatefile("${path.module}/../../app/vuln-webapp/bootstrap.sh.tpl", {
    app_py      = file("${path.module}/../../app/vuln-webapp/app.py")
    index_html  = file("${path.module}/../../app/vuln-webapp/templates/index.html")
    result_html = file("${path.module}/../../app/vuln-webapp/templates/result.html")
  })
}

# ==============================================
# Target Group Attachment 블록
# ==============================================

resource "aws_lb_target_group_attachment" "app" {
  count            = length(module.ec2.instance_ids)
  target_group_arn = module.alb_waf.target_group_arn
  target_id        = module.ec2.instance_ids[count.index]
}