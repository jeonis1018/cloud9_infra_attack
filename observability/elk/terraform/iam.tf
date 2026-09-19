data "aws_iam_policy_document" "ec2_assume" { # EC2 instance profile 전용 신뢰 정책입니다.
  statement {                                 # EC2 서비스만 이 역할을 맡을 수 있습니다.
    actions = ["sts:AssumeRole"]              # 임시 자격 증명 발급입니다.
    principals {                              # EC2 서비스 principal입니다.
      type        = "Service"                 # 서비스 유형입니다.
      identifiers = ["ec2.amazonaws.com"]     # 공식 EC2 principal입니다.
    }                                         # principal을 끝냅니다.
  }                                           # 신뢰문을 끝냅니다.
}                                             # 신뢰 정책을 끝냅니다.

resource "aws_iam_role" "node" {                                            # 장기 액세스 키 대신 역할을 세 개 만듭니다.
  tags               = { Name = "${var.name_prefix}-iam-${each.key}-role" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each           = local.roles                                          # 역할별 권한을 분리합니다.
  name               = "${var.name_prefix}-iam-${each.key}-role"            # 역할 이름입니다.
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json         # EC2 서비스만 맡을 수 있습니다.
}                                                                           # 역할 리소스를 끝냅니다.

resource "aws_iam_instance_profile" "node" {                         # 역할을 EC2에 연결하는 profile입니다.
  tags     = { Name = "${var.name_prefix}-iam-${each.key}-profile" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each = local.roles                                             # 역할별로 만듭니다.
  name     = "${var.name_prefix}-iam-${each.key}-profile"            # profile 이름입니다.
  role     = aws_iam_role.node[each.key].name                        # 대응 역할입니다.
}                                                                    # profile을 끝냅니다.

resource "aws_iam_role_policy_attachment" "ssm" {                                    # SSH 포트 없이 Systems Manager를 사용합니다.
  for_each   = local.roles                                                           # 세 서버 모두 관리 대상입니다.
  role       = aws_iam_role.node[each.key].name                                      # EC2 역할입니다.
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore" # 관리 채널에 필요한 AWS 관리 정책입니다.
}                                                                                    # SSM 권한 연결을 끝냅니다.

resource "aws_iam_role_policy" "artifacts" {                                       # 각 서버는 자기 배포 파일만 읽습니다.
  for_each = local.roles                                                           # 세 역할입니다.
  name     = "${var.name_prefix}-iam-${each.key}-read-artifacts"                   # 정책 이름입니다.
  role     = aws_iam_role.node[each.key].id                                        # 대응 역할입니다.
  policy = jsonencode({                                                            # 역할별 임시 파일 읽기 정책입니다.
    Version = "2012-10-17"                                                         # 정책 버전입니다.
    Statement = [                                                                  # 동작별로 범위를 나눕니다.
      {                                                                            # 자기 prefix의 목록만 조회합니다.
        Effect   = "Allow"                                                         # 허용문입니다.
        Action   = ["s3:ListBucket"]                                               # 버킷 목록 조회입니다.
        Resource = aws_s3_bucket.data["artifacts"].arn                             # 아티팩트 버킷만 허용합니다.
        Condition = {                                                              # 다른 역할 prefix를 열거하지 못하게 합니다.
          StringLike = { "s3:prefix" = ["${each.key}", "${each.key}/*"] }          # 자기 역할 경로만 허용합니다.
        }                                                                          # 조건을 끝냅니다.
      },                                                                           # 목록 허용문을 끝냅니다.
      {                                                                            # 자기 역할의 파일 내용만 읽습니다.
        Effect   = "Allow"                                                         # 허용문입니다.
        Action   = ["s3:GetObject"]                                                # 쓰기·삭제 권한은 없습니다.
        Resource = "${aws_s3_bucket.data["artifacts"].arn}/${each.key}/*"          # 역할별 경로입니다.
      },                                                                           # 객체 읽기문을 끝냅니다.
      {                                                                            # S3를 통해 자기 아티팩트를 복호화합니다.
        Effect   = "Allow"                                                         # 허용문입니다.
        Action   = ["kms:Decrypt"]                                                 # 암호화 키 관리 권한은 없습니다.
        Resource = aws_kms_key.artifacts.arn                                       # 아티팩트 CMK만 허용합니다.
        Condition = {                                                              # S3 경유 사용으로 제한합니다.
          StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" } # 직접 KMS 호출은 허용하지 않습니다.
        }                                                                          # 조건을 끝냅니다.
      }                                                                            # 복호화문을 끝냅니다.
    ]                                                                              # 허용문 목록을 끝냅니다.
  })                                                                               # 정책 JSON을 끝냅니다.
}                                                                                  # 아티팩트 권한을 끝냅니다.

resource "aws_iam_role_policy" "collector" {                                                                                               # 수집 서버는 원본 읽기와 알림 소비만 합니다.
  name = "${var.name_prefix}-iam-collector-read-raw-and-sqs"                                                                               # 정책 이름입니다.
  role = aws_iam_role.node["collector"].id                                                                                                 # 수집 서버 역할입니다.
  policy = jsonencode({                                                                                                                    # 동작별 최소 범위 정책입니다.
    Version = "2012-10-17"                                                                                                                 # 정책 버전입니다.
    Statement = concat([                                                                                                                   # 기본 원본 권한과 선택 기존 Trail 권한을 합칩니다.
      {                                                                                                                                    # 원본 버킷의 경로와 리전을 읽습니다.
        Effect   = "Allow"                                                                                                                 # 허용문입니다.
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]                                                                               # Filebeat 조회와 재수집에 사용합니다.
        Resource = aws_s3_bucket.data["raw"].arn                                                                                           # 신규 원본 버킷입니다.
      },                                                                                                                                   # 버킷 조회문을 끝냅니다.
      {                                                                                                                                    # 원본 객체를 읽되 삭제하지 못하게 합니다.
        Effect   = "Allow"                                                                                                                 # 허용문입니다.
        Action   = ["s3:GetObject", "s3:GetObjectVersion"]                                                                                 # 현재·과거 버전 재처리 지원입니다.
        Resource = "${aws_s3_bucket.data["raw"].arn}/*"                                                                                    # 신규 원본 버킷 안입니다.
      },                                                                                                                                   # 객체 조회문을 끝냅니다.
      {                                                                                                                                    # 네 소스 큐만 소비합니다.
        Effect   = "Allow"                                                                                                                 # 허용문입니다.
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes", "sqs:GetQueueUrl"] # Filebeat가 필요한 동작입니다.
        Resource = [for queue in aws_sqs_queue.source : queue.arn]                                                                         # DLQ는 자동 소비하지 않습니다.
      },                                                                                                                                   # SQS 소비문을 끝냅니다.
      {                                                                                                                                    # 신규 원본의 암호화를 풉니다.
        Effect   = "Allow"                                                                                                                 # 허용문입니다.
        Action   = ["kms:Decrypt"]                                                                                                         # 키 관리·삭제는 불가능합니다.
        Resource = aws_kms_key.raw.arn                                                                                                     # 신규 원본 CMK입니다.
        Condition = {                                                                                                                      # S3 전달 요청만 허용합니다.
          StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" }                                                         # S3 경유 복호화입니다.
        }                                                                                                                                  # 조건을 끝냅니다.
      }                                                                                                                                    # 신규 원본 복호화문을 끝냅니다.
      ], jsondecode(var.existing_cloudtrail_bucket_name != null ? jsonencode([                                                             # 기존 Trail 사용 시만 권한을 추가하고 조건문의 객체 형식을 안전하게 통일합니다.
        {                                                                                                                                  # 기존 버킷의 지정 prefix만 목록 조회합니다.
          Effect   = "Allow"                                                                                                               # 허용문입니다.
          Action   = ["s3:ListBucket"]                                                                                                     # 객체 목록 조회입니다.
          Resource = local.cloudtrail_bucket_arn                                                                                           # 기존 버킷 ARN입니다.
          Condition = {                                                                                                                    # 원래 버킷의 다른 로그는 열거하지 못하게 합니다.
            StringLike = { "s3:prefix" = ["${var.existing_cloudtrail_object_prefix}*"] }                                                   # 일반 이벤트 prefix입니다.
          }                                                                                                                                # 조건을 끝냅니다.
        },                                                                                                                                 # 목록 권한을 끝냅니다.
        {                                                                                                                                  # 기존 버킷 리전을 확인합니다.
          Effect   = "Allow"                                                                                                               # 허용문입니다.
          Action   = ["s3:GetBucketLocation"]                                                                                              # 지역 조회입니다.
          Resource = local.cloudtrail_bucket_arn                                                                                           # 기존 버킷만 허용합니다.
        },                                                                                                                                 # 리전 조회문을 끝냅니다.
        {                                                                                                                                  # 기존 Trail 객체를 읽습니다.
          Effect   = "Allow"                                                                                                               # 허용문입니다.
          Action   = ["s3:GetObject", "s3:GetObjectVersion"]                                                                               # 현재·과거 버전 읽기입니다.
          Resource = "${local.cloudtrail_bucket_arn}/${var.existing_cloudtrail_object_prefix}*"                                            # 확인한 경로만 허용합니다.
        }                                                                                                                                  # 기존 객체 읽기문을 끝냅니다.
        ]) : "[]"), jsondecode(length(var.existing_cloudtrail_kms_key_arns) > 0 ? jsonencode([                                             # 기존 CMK 목록이 있으면 추가합니다.
        {                                                                                                                                  # 기존 키 정책도 이 역할을 허용해야 동작합니다.
          Effect   = "Allow"                                                                                                               # IAM 쪽 허용문입니다.
          Action   = ["kms:Decrypt"]                                                                                                       # 복호화만 허용합니다.
          Resource = var.existing_cloudtrail_kms_key_arns                                                                                  # 명시적으로 입력한 기존 키입니다.
          Condition = {                                                                                                                    # S3 요청으로 제한합니다.
            StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" }                                                       # 같은 리전 S3 경유입니다.
          }                                                                                                                                # 조건을 끝냅니다.
        }                                                                                                                                  # 기존 복호화문을 끝냅니다.
    ]) : "[]"))                                                                                                                            # 선택 권한 결합을 끝냅니다.
  })                                                                                                                                       # JSON을 끝냅니다.
}                                                                                                                                          # collector 정책을 끝냅니다.

resource "aws_iam_role_policy" "snapshots" {                                                                                     # ES 역할에는 스냅샷 저장소만 쓰기 권한을 줍니다.
  name = "${var.name_prefix}-iam-elasticsearch-manage-snapshots"                                                                 # 정책 이름입니다.
  role = aws_iam_role.node["elasticsearch"].id                                                                                   # ES 전용 역할입니다.
  policy = jsonencode({                                                                                                          # repository-s3가 사용하는 권한입니다.
    Version = "2012-10-17"                                                                                                       # 정책 버전입니다.
    Statement = [                                                                                                                # 버킷·객체 동작을 분리합니다.
      {                                                                                                                          # 저장소를 열거하고 위치를 확인합니다.
        Effect   = "Allow"                                                                                                       # 허용문입니다.
        Action   = ["s3:ListBucket", "s3:GetBucketLocation", "s3:ListBucketMultipartUploads"]                                    # 저장소 버킷 조회입니다.
        Resource = aws_s3_bucket.data["snapshots"].arn                                                                           # 별도 스냅샷 버킷입니다.
      },                                                                                                                         # 버킷 조회문을 끝냅니다.
      {                                                                                                                          # 저장소 파일의 생성·읽기·정리를 허용합니다.
        Effect   = "Allow"                                                                                                       # 허용문입니다.
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"] # 스냅샷 저장소 관리 동작입니다.
        Resource = "${aws_s3_bucket.data["snapshots"].arn}/*"                                                                    # 원본 버킷은 포함하지 않습니다.
      }                                                                                                                          # 객체 동작을 끝냅니다.
    ]                                                                                                                            # 허용문 목록을 끝냅니다.
  })                                                                                                                             # 정책 JSON을 끝냅니다.
}                                                                                                                                # 스냅샷 권한을 끝냅니다.

resource "aws_iam_role" "firehose" {                                         # 각 Firehose에 쓰기 역할을 분리합니다.
  tags     = { Name = "${var.name_prefix}-iam-${each.key}-firehose-role" }   # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each = local.cwl_sources                                               # CWL과 WAF 두 스트림입니다.
  name     = "${var.name_prefix}-iam-${each.key}-firehose-role"              # 역할 이름입니다.
  assume_role_policy = jsonencode({                                          # Firehose 전용 신뢰 정책입니다.
    Version = "2012-10-17"                                                   # 정책 버전입니다.
    Statement = [{                                                           # 서비스 역할 위임문입니다.
      Effect    = "Allow"                                                    # 위임을 허용합니다.
      Principal = { Service = "firehose.amazonaws.com" }                     # Firehose 서비스만 허용합니다.
      Action    = "sts:AssumeRole"                                           # 임시 역할 위임입니다.
      Condition = { StringEquals = { "sts:ExternalId" = local.account_id } } # Firehose가 제공하는 계정 ID를 확인합니다.
    }]                                                                       # 위임문을 끝냅니다.
  })                                                                         # 신뢰 JSON을 끝냅니다.
}                                                                            # Firehose 역할을 끝냅니다.

resource "aws_iam_role_policy" "firehose" {                                                                                             # 정상·실패 prefix와 전달 오류 로그에만 접근합니다.
  for_each = local.cwl_sources                                                                                                          # 두 스트림 각각입니다.
  name     = "${var.name_prefix}-iam-${each.key}-deliver-to-s3"                                                                         # 정책 이름입니다.
  role     = aws_iam_role.firehose[each.key].id                                                                                         # 대응 Firehose 역할입니다.
  policy = jsonencode({                                                                                                                 # 서비스 동작을 최소 범위로 허용합니다.
    Version = "2012-10-17"                                                                                                              # 정책 버전입니다.
    Statement = [                                                                                                                       # 동작별 권한문입니다.
      {                                                                                                                                 # 목적지 버킷 상태를 조회합니다.
        Effect   = "Allow"                                                                                                              # 허용문입니다.
        Action   = ["s3:GetBucketLocation", "s3:ListBucket", "s3:ListBucketMultipartUploads"]                                           # Firehose 전달에 필요한 조회입니다.
        Resource = aws_s3_bucket.data["raw"].arn                                                                                        # 신규 원본 버킷입니다.
      },                                                                                                                                # 버킷 조회문을 끝냅니다.
      {                                                                                                                                 # 전달 파일과 오류 파일을 씁니다.
        Effect   = "Allow"                                                                                                              # 허용문입니다.
        Action   = ["s3:AbortMultipartUpload", "s3:GetObject", "s3:PutObject"]                                                          # Firehose 공식 전달 권한입니다.
        Resource = ["${aws_s3_bucket.data["raw"].arn}/${each.key}/*", "${aws_s3_bucket.data["raw"].arn}/firehose-errors/${each.key}/*"] # 소스별 경로 제한입니다.
      },                                                                                                                                # 객체 전달문을 끝냅니다.
      {                                                                                                                                 # S3 SSE-KMS 객체를 암호화합니다.
        Effect    = "Allow"                                                                                                             # 허용문입니다.
        Action    = ["kms:GenerateDataKey", "kms:Decrypt"]                                                                              # multipart 등에서 복호화도 요구됩니다.
        Resource  = aws_kms_key.raw.arn                                                                                                 # 원본 CMK입니다.
        Condition = { StringEquals = { "kms:ViaService" = "s3.${local.region}.amazonaws.com" } }                                        # S3 경유로 제한합니다.
      },                                                                                                                                # 암호화 권한을 끝냅니다.
      {                                                                                                                                 # 전달 오류를 CloudWatch에 기록합니다.
        Effect   = "Allow"                                                                                                              # 허용문입니다.
        Action   = ["logs:PutLogEvents"]                                                                                                # 로그 그룹/스트림 생성은 Terraform이 담당합니다.
        Resource = aws_cloudwatch_log_stream.firehose[each.key].arn                                                                     # 자기 오류 스트림만 허용합니다.
      }                                                                                                                                 # 오류 기록문을 끝냅니다.
    ]                                                                                                                                   # 권한문 목록을 끝냅니다.
  })                                                                                                                                    # JSON을 끝냅니다.
}                                                                                                                                       # Firehose 권한을 끝냅니다.

resource "aws_iam_role" "subscription" {                                                                                     # CloudWatch Logs가 Firehose에 넣는 역할입니다.
  tags     = { Name = "${var.name_prefix}-iam-${each.key}-subscription-role" }                                               # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each = local.cwl_sources                                                                                               # 두 소스입니다.
  name     = "${var.name_prefix}-iam-${each.key}-subscription-role"                                                          # 역할 이름입니다.
  assume_role_policy = jsonencode({                                                                                          # CloudWatch Logs 서비스 신뢰입니다.
    Version = "2012-10-17"                                                                                                   # 정책 버전입니다.
    Statement = [{                                                                                                           # 구독 전달 역할 위임문입니다.
      Effect    = "Allow"                                                                                                    # 허용문입니다.
      Principal = { Service = "logs.amazonaws.com" }                                                                         # CloudWatch Logs 서비스입니다.
      Action    = "sts:AssumeRole"                                                                                           # 역할 위임 동작입니다.
      Condition = { StringLike = { "aws:SourceArn" = "arn:${local.partition}:logs:${local.region}:${local.account_id}:*" } } # 현재 계정·리전 로그만 허용합니다.
    }]                                                                                                                       # 허용문을 끝냅니다.
  })                                                                                                                         # JSON을 끝냅니다.
}                                                                                                                            # 구독 역할을 끝냅니다.

resource "aws_iam_role_policy" "subscription" {                            # 구독 역할은 대응 스트림에 쓰기만 합니다.
  for_each = local.cwl_sources                                             # 두 소스입니다.
  name     = "${var.name_prefix}-iam-${each.key}-put-to-firehose"          # 정책 이름입니다.
  role     = aws_iam_role.subscription[each.key].id                        # 대응 구독 역할입니다.
  policy = jsonencode({                                                    # Firehose 쓰기 정책입니다.
    Version = "2012-10-17"                                                 # 정책 버전입니다.
    Statement = [{                                                         # 쓰기 허용문입니다.
      Effect   = "Allow"                                                   # 허용문입니다.
      Action   = ["firehose:PutRecord", "firehose:PutRecordBatch"]         # 구독 전달 동작입니다.
      Resource = aws_kinesis_firehose_delivery_stream.source[each.key].arn # 자기 소스 Firehose만 허용합니다.
    }]                                                                     # 허용문을 끝냅니다.
  })                                                                       # JSON을 끝냅니다.
}                                                                          # 구독 권한을 끝냅니다.
