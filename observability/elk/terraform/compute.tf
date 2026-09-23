resource "aws_security_group" "node" {                           # 역할별로 별도 보안 그룹을 만듭니다.
  tags        = { Name = "${var.name_prefix}-sg-${each.key}" }   # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each    = local.roles                                      # 세 역할에 각각 적용합니다.
  name        = "${var.name_prefix}-sg-${each.key}"              # 사람이 구분 가능한 이름입니다.
  description = "ELK validation ${each.key}; access through SSM" # 관리 접속은 SSM으로 제한합니다.
  vpc_id      = var.vpc_id                                       # 기존 VPC에 생성합니다.
}                                                                # 기본으로 인바운드가 없는 그룹입니다.

resource "aws_vpc_security_group_egress_rule" "https" {                           # 패키지 저장소와 AWS API에 HTTPS 연결을 허용합니다.
  tags              = { Name = "${var.name_prefix}-sg-${each.key}-https-egress" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each          = local.roles                                                 # 세 EC2에 공통 적용합니다.
  security_group_id = aws_security_group.node[each.key].id                        # 해당 역할 그룹입니다.
  ip_protocol       = "tcp"                                                       # HTTPS는 TCP입니다.
  from_port         = 443                                                         # 목적지 포트입니다.
  to_port           = 443                                                         # HTTPS 포트만 허용합니다.
  cidr_ipv4         = "0.0.0.0/0"                                                 # 외부 접근은 기존 NAT 또는 endpoint가 실제 경로를 제공합니다.
  description       = "HTTPS to package repositories and AWS APIs"                # 허용 목적을 기록합니다.
}                                                                                 # HTTPS 송신 규칙을 끝냅니다.

resource "aws_vpc_security_group_egress_rule" "apt_http" {                                 # Ubuntu 기본 apt 저장소는 HTTP일 수 있습니다.
  tags              = { Name = "${var.name_prefix}-sg-${each.key}-apt-egress" }            # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each          = local.roles                                                          # 설치 단계에서 세 서버가 사용합니다.
  security_group_id = aws_security_group.node[each.key].id                                 # 해당 역할 그룹입니다.
  ip_protocol       = "tcp"                                                                # 패키지 저장소 전송 프로토콜입니다.
  from_port         = 80                                                                   # HTTP 포트입니다.
  to_port           = 80                                                                   # HTTP 포트만 허용합니다.
  cidr_ipv4         = "0.0.0.0/0"                                                          # NAT 경로가 있어야 실제 통신됩니다.
  description       = "Ubuntu package downloads; remove after HTTPS-only mirror migration" # HTTPS 저장소로 바꾼 뒤 제거할 수 있습니다.
}                                                                                          # 설치용 송신 규칙을 끝냅니다.

resource "aws_vpc_security_group_ingress_rule" "es" {                                              # ES REST API는 collector와 Kibana만 접근합니다.
  tags                         = { Name = "${var.name_prefix}-sg-elasticsearch-from-${each.key}" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each                     = toset(["collector", "kibana"])                                    # 접근 주체 두 개입니다.
  security_group_id            = aws_security_group.node["elasticsearch"].id                       # 목적지 ES 그룹입니다.
  referenced_security_group_id = aws_security_group.node[each.key].id                              # 허용할 소스 그룹입니다.
  ip_protocol                  = "tcp"                                                             # HTTPS API의 전송 계층입니다.
  from_port                    = 9200                                                              # Elasticsearch REST 포트입니다.
  to_port                      = 9200                                                              # 단일 포트만 열어 둡니다.
  description                  = "${each.key} to Elasticsearch TLS API"                            # 허용 목적입니다.
}                                                                                                  # ES 인바운드 규칙을 끝냅니다.

resource "aws_vpc_security_group_egress_rule" "to_es" {                                          # 최소 송신 규칙으로 ES 연결을 추가합니다.
  tags                         = { Name = "${var.name_prefix}-sg-${each.key}-to-elasticsearch" } # 새 자원의 콘솔 이름도 통일된 서비스·역할 규칙으로 표시합니다.
  for_each                     = toset(["collector", "kibana"])                                  # ES를 사용하는 두 서버입니다.
  security_group_id            = aws_security_group.node[each.key].id                            # 송신 그룹입니다.
  referenced_security_group_id = aws_security_group.node["elasticsearch"].id                     # 목적지 그룹입니다.
  ip_protocol                  = "tcp"                                                           # TCP 연결입니다.
  from_port                    = 9200                                                            # 목적지 ES 포트입니다.
  to_port                      = 9200                                                            # 9200만 허용합니다.
  description                  = "Elasticsearch TLS API"                                         # 허용 목적입니다.
}                                                                                                # ES 송신 규칙을 끝냅니다.

resource "aws_instance" "node" {                                                  # EC2 세 대를 생성하고 소프트웨어 설치는 별도 절차로 수행합니다.
  for_each                    = local.roles                                       # collector, elasticsearch, kibana입니다.
  ami                         = local.selected_ami                                # Ubuntu 24.04 amd64 AMI입니다.
  instance_type               = var.instance_types[each.key]                      # 역할별 시작 사양입니다.
  subnet_id                   = var.private_subnet_ids[each.key]                  # 선택한 private subnet입니다.
  associate_public_ip_address = false                                             # 공인 IP를 부여하지 않습니다.
  vpc_security_group_ids      = [aws_security_group.node[each.key].id]            # 역할별 접근 제한입니다.
  iam_instance_profile        = aws_iam_instance_profile.node[each.key].name      # 키 파일 대신 EC2 역할을 사용합니다.
  monitoring                  = false                                             # 초기에는 기본 EC2 지표를 사용합니다.
  metadata_options {                                                              # Instance Metadata Service 접근을 보호합니다.
    http_endpoint               = "enabled"                                       # EC2 역할 임시 자격 증명 제공이 필요합니다.
    http_tokens                 = "required"                                      # IMDSv2 토큰을 필수로 합니다.
    http_put_response_hop_limit = 1                                               # 호스트에서 실행하는 서비스만 사용하는 구성입니다.
  }                                                                               # IMDS 설정을 끝냅니다.
  root_block_device {                                                             # root EBS에 OS와 검증용 서비스 데이터를 저장합니다.
    tags                  = { Name = "${var.name_prefix}-ebs-${each.key}-root" }  # 자동 생성 root EBS도 역할별 이름으로 식별합니다.
    encrypted             = true                                                  # EBS 기본 관리 키로 암호화합니다.
    volume_type           = "gp3"                                                 # 범용 SSD를 사용합니다.
    volume_size           = var.root_volume_gib[each.key]                         # 역할별 디스크 용량입니다.
    delete_on_termination = false                                                 # 인스턴스 종료 시 데이터 볼륨을 자동 삭제하지 않습니다.
  }                                                                               # 디스크 설정을 끝냅니다.
  tags = {                                                                        # 콘솔 표시용 태그입니다.
    Name = "${var.name_prefix}-ec2-${each.key}"                                   # 서버 역할을 이름에 표시합니다.
    Role = each.key                                                               # 역할별 검색용 태그입니다.
  }                                                                               # 태그 설정을 끝냅니다.
  lifecycle {                                                                     # 잘못된 subnet 배포와 의도치 않은 AMI 교체를 막습니다.
    ignore_changes = [ami]                                                        # AMI 업데이트는 명시적인 교체 계획으로 진행합니다.
    precondition {                                                                # 다른 VPC subnet 입력을 차단합니다.
      condition     = data.aws_subnet.selected[each.key].vpc_id == var.vpc_id     # 모든 subnet이 선택한 VPC여야 합니다.
      error_message = "private_subnet_ids의 모든 subnet은 vpc_id에 속해야 합니다."           # 오류를 안내합니다.
    }                                                                             # 사전조건을 끝냅니다.
    precondition {                                                                # 공인 IP 자동 부여 subnet의 실수를 막습니다.
      condition     = !data.aws_subnet.selected[each.key].map_public_ip_on_launch # 실제 route table private 여부는 별도 점검합니다.
      error_message = "자동 공인 IP 할당이 해제된 private subnet을 선택하세요."                   # 오류를 안내합니다.
    }                                                                             # 사전조건을 끝냅니다.
  }                                                                               # 수명주기 설정을 끝냅니다.
}                                                                                 # EC2 생성을 끝냅니다.

resource "aws_vpc_endpoint" "s3" {                           # S3 gateway endpoint만 선택적으로 구성합니다.
  count             = var.create_s3_gateway_endpoint ? 1 : 0 # 기존 endpoint가 있으면 생성하지 않습니다.
  vpc_id            = var.vpc_id                             # 기존 VPC에 연결합니다.
  service_name      = "com.amazonaws.${local.region}.s3"     # 같은 리전의 S3입니다.
  vpc_endpoint_type = "Gateway"                              # 시간당 endpoint 요금이 없는 gateway 유형입니다.
  route_table_ids   = var.private_route_table_ids            # 이 route table에 S3 경로를 추가합니다.
  tags = {                                                   # 목적을 표시합니다.
    Name = "${var.name_prefix}-vpce-s3-access"               # endpoint 이름입니다.
  }                                                          # 태그를 끝냅니다.
}                                                            # endpoint 생성을 끝냅니다.
