terraform {                               # CLI와 공급자 버전을 고정합니다.
  required_version = ">= 1.10.0, < 2.0.0" # S3 상태 잠금 기능을 지원하는 버전 이상을 사용합니다.
  required_providers {                    # 이 모듈의 외부 공급자를 선언합니다.
    aws = {                               # AWS 리소스를 관리합니다.
      source  = "hashicorp/aws"           # 공식 AWS 공급자를 사용합니다.
      version = "~> 6.0"                  # 검증한 6.x 범위로 제한하고 lock 파일로 실제 버전을 고정합니다.
    }                                     # AWS 공급자 선언을 끝냅니다.
  }                                       # 공급자 요구사항을 끝냅니다.
}                                         # Terraform 요구사항을 끝냅니다.

provider "aws" {                                  # 기존 자격 증명 체인을 사용하며 코드에 키를 넣지 않습니다.
  region              = var.aws_region            # 사전에 확인한 리전을 사용합니다.
  allowed_account_ids = [var.expected_account_id] # 다른 계정에 잘못 배포하는 것을 차단합니다.
  default_tags {                                  # 모든 지원 리소스에 기본 태그를 적용합니다.
    tags = {                                      # 비용 추적과 소유권을 표시합니다.
      Project   = var.name_prefix                 # 프로젝트를 식별합니다.
      ManagedBy = "Terraform"                     # 콘솔과 Terraform의 중복 관리를 방지합니다.
      Purpose   = "ELK-single-node-validation"    # 단일 노드 검증 환경임을 표시합니다.
    }                                             # 태그 목록을 끝냅니다.
  }                                               # 기본 태그를 끝냅니다.
}                                                 # 공급자 설정을 끝냅니다.
