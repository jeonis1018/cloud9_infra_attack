# ==============================================
# provider 설정
# ==============================================

terraform {
  required_version = ">= 1.5.0"

  backend "s3" {
      bucket = "cloud943-attack-tfstate"
      key    = "envs/before/terraform.tfstate"
      region = "ap-northeast-2"
      profile = "cloud943"   # profile명에 맞게 수정 필요
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
    # GuardDuty 정규화 Lambda 소스를 zip으로 묶는 데 사용한다
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4"
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

  s3_bucket_arn      = module.s3_endpoint.bucket_arn
  profile_bucket_arn = module.s3_endpoint.profile_bucket_arn

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
    app_py              = file("${path.module}/../../app/vuln-webapp/app.py")
    index_html          = file("${path.module}/../../app/vuln-webapp/templates/index.html")
    profile_bucket_name = module.s3_endpoint.profile_bucket_id
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

# ==============================================
# GuardDuty 파인딩 정규화 블록
#
# apply 후 동작:
#   GuardDuty 파인딩 발생
#     -> EventBridge 룰
#     -> CloudWatch Logs (/aws/events/cloud9-security/guardduty)
#     -> 구독 필터
#     -> normalize-guardduty-logs-v2
#     -> s3://<버킷>/guardduty/year=/month=/day=/hour=/<파인딩ID>.json
#
# S3 버킷은 이 state가 소유하지 않는다 (이름으로만 참조하므로 기존 버킷과 충돌 없음).
# ==============================================

module "guardduty_normalizer" {
  source = "../../modules/guardduty-normalizer"

  lambda_source_file = "${path.module}/../../Lambda/GuardDuty/normalize-guardduty-logs-v2.py"
  normalized_bucket  = var.normalized_bucket

  # 파인딩 전달 경로(로그 그룹 + EventBridge 룰)를 이 모듈이 만들지 여부
  create_finding_delivery = var.create_finding_delivery

  # 룰 평가 Lambda가 배포되어 있으면 이름을 넣는다 (비우면 정규화까지만 수행)
  rules_function_name = var.rules_function_name
}