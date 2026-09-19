variable "aws_region" {                                                       # 리전은 모든 S3·SQS·KMS·EC2에 공통 적용합니다.
  type    = string                                                            # 리전 이름을 문자열로 받습니다.
  default = "ap-northeast-2"                                                  # 서울 리전을 기본으로 합니다.
  validation {                                                                # 이 예제의 서비스 principal과 콘솔 안내 범위를 제한합니다.
    condition     = contains(["ap-northeast-2", "us-east-1"], var.aws_region) # CloudFront WAF는 us-east-1 별도 스택이 필요합니다.
    error_message = "이 가이드는 ap-northeast-2 또는 us-east-1 단일 리전만 검증 대상으로 합니다."  # 잘못된 리전을 설명합니다.
  }                                                                           # 검증을 끝냅니다.
}                                                                             # 변수 선언을 끝냅니다.

variable "expected_account_id" {                                       # 배포할 계정을 명시적으로 선택합니다.
  type = string                                                        # 계정 ID는 숫자가 아닌 문자열입니다.
  validation {                                                         # 형식을 확인합니다.
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id)) # 정확히 12자리여야 합니다.
    error_message = "AWS 계정 ID 12자리를 입력하세요."                           # 오류를 안내합니다.
  }                                                                    # 검증을 끝냅니다.
}                                                                      # 변수 선언을 끝냅니다.

variable "name_prefix" {                                          # 전역 버킷 이름과 서비스 이름의 공통 접두사입니다.
  type    = string                                                # 소문자 문자열입니다.
  default = "whs-elk"                                             # 예제 기본값입니다.
  validation {                                                    # 서비스 이름 제한을 만족시킵니다.
    condition     = var.name_prefix == "whs-elk"                  # 모든 신규 자원의 통일된 접두사를 고정합니다.
    error_message = "새 자원 이름의 통일을 위해 name_prefix는 whs-elk여야 합니다." # 허용 형식을 안내합니다.
  }                                                               # 검증을 끝냅니다.
}                                                                 # 변수 선언을 끝냅니다.

variable "vpc_id" { # 기존 VPC를 재사용하고 여기서 수정하지 않습니다.
  type = string     # vpc-... ID를 입력합니다.
}                   # 변수 선언을 끝냅니다.

variable "private_subnet_ids" { # 역할별 private subnet을 선택합니다.
  type = object({               # 한 subnet을 중복 지정해도 되지만 운영 확장 시 AZ를 분리합니다.
    collector     = string      # Filebeat와 Logstash가 함께 실행될 subnet입니다.
    elasticsearch = string      # Elasticsearch 단일 노드의 subnet입니다.
    kibana        = string      # Kibana 단일 노드의 subnet입니다.
  })                            # 객체 자료형을 끝냅니다.
}                               # 변수 선언을 끝냅니다.

variable "instance_types" {     # 작은 검증 환경의 시작 사양이며 측정 후 조정합니다.
  type = object({               # amd64/x86_64 인스턴스만 선택합니다.
    collector     = string      # Filebeat+Logstash용 사양입니다.
    elasticsearch = string      # 색인·검색용 사양입니다.
    kibana        = string      # 대시보드용 사양입니다.
  })                            # 객체 자료형을 끝냅니다.
  default = {                   # 무료 사용량이나 생산 용량 보장이 아닌 시작 가정입니다.
    collector     = "t3.large"  # 2 vCPU·8 GiB 메모리로 시작합니다.
    elasticsearch = "t3.large"  # 2 vCPU·8 GiB 메모리로 시작합니다.
    kibana        = "t3.medium" # 2 vCPU·4 GiB 메모리로 시작합니다.
  }                             # 기본 사양을 끝냅니다.
}                               # 변수 선언을 끝냅니다.

variable "root_volume_gib" { # 검증 간편화를 위해 서비스 데이터도 암호화 root EBS를 사용합니다.
  type = object({            # 운영에서는 데이터 EBS 분리를 권장합니다.
    collector     = number   # PQ와 Filebeat 상태 저장 공간입니다.
    elasticsearch = number   # 인덱스 저장 공간입니다.
    kibana        = number   # OS와 Kibana 설치 공간입니다.
  })                         # 자료형 선언을 끝냅니다.
  default = {                # 이 값은 보관 용량 산정의 대체물이 아닙니다.
    collector     = 50       # GiB 단위입니다.
    elasticsearch = 100      # GiB 단위입니다.
    kibana        = 30       # GiB 단위입니다.
  }                          # 기본값을 끝냅니다.
}                            # 변수 선언을 끝냅니다.

variable "ami_id" { # 최초 확인한 AMI ID를 나중에 고정하기 위한 선택 변수입니다.
  type     = string # ami-... ID 또는 null을 받습니다.
  default  = null   # 최초 계획에서는 Canonical SSM의 최신 Ubuntu 24.04를 조회합니다.
  nullable = true   # null이면 자동 조회합니다.
}                   # 변수 선언을 끝냅니다.

variable "raw_retention_days" {                                                    # 원본의 현재 버전 보관 기간입니다.
  type    = number                                                                 # 일 단위로 받습니다.
  default = 30                                                                     # 프로젝트의 한 달 보관 가정입니다.
  validation {                                                                     # 14일 큐 보관보다 원본을 오래 남깁니다.
    condition     = var.raw_retention_days >= 30 && var.raw_retention_days <= 3650 # 검증용 허용 범위입니다.
    error_message = "원본 보관 기간은 30~3650일로 지정하세요."                                   # 잘못된 기간을 설명합니다.
  }                                                                                # 검증을 끝냅니다.
}                                                                                  # 변수 선언을 끝냅니다.

variable "existing_log_group_names" { # 소스 로그 그룹의 소유권을 선택합니다.
  type = object({                     # null이면 이 Terraform이 새로 만듭니다.
    cloudwatch = optional(string)     # Agent가 이미 쓰는 로그 그룹을 재사용할 수 있습니다.
    waf        = optional(string)     # 기존 WAF 로그 그룹을 재사용할 수 있습니다.
  })                                  # 자료형 선언을 끝냅니다.
  default = {}                        # 두 그룹을 신규 생성합니다.
}                                     # 변수 선언을 끝냅니다.

variable "create_cloudtrail" {                                                                # 조직 Trail/기존 Trail 중복 기록을 피하기 위한 선택입니다.
  type    = bool                                                                              # 새 계정 Trail 생성 여부입니다.
  default = false                                                                             # 기존 Trail 확인 후 필요할 때만 true로 변경합니다.
  validation {                                                                                # 신규 Trail과 기존 버킷 수집은 둘 중 하나를 선택합니다.
    condition     = !var.create_cloudtrail || var.existing_cloudtrail_bucket_name == null     # 동일 큐의 소스 소유권을 명확히 합니다.
    error_message = "create_cloudtrail=true와 existing_cloudtrail_bucket_name은 함께 사용할 수 없습니다." # 오류를 안내합니다.
  }                                                                                           # 검증을 끝냅니다.
}                                                                                             # 변수 선언을 끝냅니다.

variable "existing_cloudtrail_bucket_name" { # 기존 Trail의 목적지 변경 없이 원본을 읽는 선택입니다.
  type     = string                          # 같은 계정·리전 버킷 이름입니다.
  default  = null                            # 지정하지 않으면 기존 버킷을 읽지 않습니다.
  nullable = true                            # 미사용을 null로 표현합니다.
}                                            # 변수 선언을 끝냅니다.

variable "existing_cloudtrail_object_prefix" {                                                                                                 # 기존 버킷 안에서 일반 이벤트가 저장되는 정확한 경로입니다.
  type     = string                                                                                                                            # 예: AWSLogs/123456789012/CloudTrail/입니다.
  default  = null                                                                                                                              # 기존 버킷을 쓸 때 반드시 입력합니다.
  nullable = true                                                                                                                              # 기존 버킷 미사용 시 비워 둡니다.
  validation {                                                                                                                                 # digest와 다른 조직 계정 경로를 무분별하게 읽지 않도록 합니다.
    condition     = var.existing_cloudtrail_bucket_name == null || try(endswith(var.existing_cloudtrail_object_prefix, "/CloudTrail/"), false) # 확인한 CloudTrail 이벤트 경로입니다.
    error_message = "기존 버킷 수집에는 /CloudTrail/로 끝나는 실제 이벤트 객체 prefix가 필요합니다."                                                                    # 경로를 안내합니다.
  }                                                                                                                                            # 검증을 끝냅니다.
}                                                                                                                                              # 변수 선언을 끝냅니다.

variable "existing_cloudtrail_kms_key_arns" { # 기존 CMK로 암호화된 로그의 복호화 키 목록입니다.
  type    = set(string)                       # 키 회전/기존키 혼재 시 여러 ARN을 입력합니다.
  default = []                                # SSE-S3 또는 미사용이면 비웁니다.
}                                             # 변수 선언을 끝냅니다.

variable "create_guardduty_detector" {                                                # GuardDuty가 전혀 없는 테스트 계정에서만 선택합니다.
  type    = bool                                                                      # 새 리전 detector 생성 여부입니다.
  default = false                                                                     # 기존 detector를 기본으로 재사용합니다.
  validation {                                                                        # 같은 리전에 detector 중복 생성 시도를 막습니다.
    condition     = !var.create_guardduty_detector || var.guardduty_detector_id == "" # 신규와 기존 ID는 상호 배타적입니다.
    error_message = "새 GuardDuty detector 생성 시 guardduty_detector_id를 비워 두세요."        # 오류를 안내합니다.
  }                                                                                   # 검증을 끝냅니다.
}                                                                                     # 변수 선언을 끝냅니다.

variable "guardduty_detector_id" { # 기존 활성 GuardDuty detector를 선택합니다.
  type    = string                 # detector ID를 받습니다.
  default = ""                     # 비어 있으면 내보내기를 만들지 않습니다.
}                                  # 변수 선언을 끝냅니다.

variable "enable_guardduty_export" {                                                                                       # 기존 publishing destination과 충돌하지 않도록 기본 해제합니다.
  type    = bool                                                                                                           # S3 내보내기 생성 여부입니다.
  default = false                                                                                                          # detector와 기존 목적지 확인 후 켭니다.
  validation {                                                                                                             # 내보내기에 detector가 필수입니다.
    condition     = !var.enable_guardduty_export || var.create_guardduty_detector || length(var.guardduty_detector_id) > 0 # 신규 또는 기존 detector를 요구합니다.
    error_message = "enable_guardduty_export=true이면 기존 detector ID 또는 신규 detector 선택이 필요합니다."                              # 원인을 안내합니다.
  }                                                                                                                        # 검증을 끝냅니다.
}                                                                                                                          # 변수 선언을 끝냅니다.

variable "waf_web_acl_arn" { # 기존 regional web ACL을 선택합니다.
  type    = string           # 전체 ARN을 받습니다.
  default = ""               # 비어 있으면 WAF 로그 설정을 변경하지 않습니다.
}                            # 변수 선언을 끝냅니다.

variable "manage_waf_logging" {                                                                                                                                         # WAF 로깅 설정의 명시적 소유권입니다.
  type    = bool                                                                                                                                                        # 기존 설정이 다른 Terraform 관리이면 사용하지 않습니다.
  default = false                                                                                                                                                       # web ACL 생성/연결은 이 패키지가 하지 않습니다.
  validation {                                                                                                                                                          # ARN과 리전 범위를 확인합니다.
    condition     = !var.manage_waf_logging || can(regex("^arn:aws:wafv2:${var.aws_region}:${var.expected_account_id}:(regional|global)/webacl/", var.waf_web_acl_arn)) # 같은 계정·리전이어야 합니다.
    error_message = "같은 계정·리전의 web ACL ARN이 필요합니다. CloudFront scope는 us-east-1에서 구성하세요."                                                                                # 오류를 안내합니다.
  }                                                                                                                                                                     # 검증을 끝냅니다.
}                                                                                                                                                                       # 변수 선언을 끝냅니다.

variable "create_s3_gateway_endpoint" { # 기존 NAT를 통하지 않는 S3 경로를 선택적으로 만듭니다.
  type    = bool                        # 같은 route table에 endpoint가 있으면 false입니다.
  default = false                       # 기존 route table 변경을 기본으로 하지 않습니다.
}                                       # 변수 선언을 끝냅니다.

variable "private_route_table_ids" {                                                           # S3 gateway endpoint를 연결할 기존 route table입니다.
  type    = set(string)                                                                        # 중복 없는 route table ID 목록입니다.
  default = []                                                                                 # endpoint를 만들지 않으면 비워 둡니다.
  validation {                                                                                 # endpoint 생성 시 경로 연결을 빠뜨리지 않습니다.
    condition     = !var.create_s3_gateway_endpoint || length(var.private_route_table_ids) > 0 # 하나 이상 필요합니다.
    error_message = "S3 endpoint 생성 시 private_route_table_ids가 필요합니다."                         # 오류를 안내합니다.
  }                                                                                            # 검증을 끝냅니다.
}                                                                                              # 변수 선언을 끝냅니다.

variable "enable_alerting" { # GuardDuty와 인프라 장애 알림 주제를 만듭니다.
  type    = bool             # SNS 구독은 자동으로 만들지 않습니다.
  default = false            # 알림 수신자 검토 후 활성화합니다.
}                            # 변수 선언을 끝냅니다.
