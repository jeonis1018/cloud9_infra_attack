# 배포 전 확인: 기존 AWS 자원과 Terraform 소유권

이 문서는 EC2 수집 서버 1대, Elasticsearch 1대, Kibana 1대를 **기존 VPC에 추가하는 첫 검증**을 기준으로 한다. 로그 플랫폼용 새 자원과 기존 업무용 자원을 먼저 구분한다. 여기에는 실제 AWS 조회·배포 결과가 포함되어 있지 않다. 아래 이름·ID는 직접 확인해 넣어야 하며, 저장소 코드가 있다는 사실만으로 배포되었다고 판단하지 않는다. 제공 Terraform은 서울 `ap-northeast-2` 또는 버지니아 `us-east-1`의 단일 리전으로 입력을 제한하며, 다른 리전은 서비스 제약과 코드를 먼저 확장해야 한다.

## 1. 적용 전에 채울 자원 목록

| 항목 | 기록할 값 | 확인할 이유 / 통과 조건 |
|---|---|---|
| 계정·리전 | AWS 계정 ID, CLI profile, 리전 | 이 가이드의 첫 구현은 동일 계정·동일 리전이다. 서울은 예시이며 실제 계정과 일치시킨다. |
| 조직 정책 | Organizations/SCP, permissions boundary, 리소스 생성 허용 범위 | IAM Allow가 있어도 SCP·경계 정책·VPC endpoint 정책의 Deny로 실패할 수 있다. |
| 기존 배포 소유자 | Terraform 작업 디렉터리, backend key, workspace, 담당자 | 동일 자원을 두 Terraform state가 동시에 관리하지 않도록 한다. state 원문에는 비밀값이 있을 수 있으므로 문서나 채팅에 복사하지 않는다. |
| VPC | ID, CIDR, DNS resolution/hostnames 설정 | 세 EC2가 서로 통신하고 AWS 서비스 이름을 해석할 수 있어야 한다. |
| Private subnet | subnet ID, AZ, 사용 가능한 IP, 연결된 route table ID | EC2 3대, 필요시 interface endpoint ENI를 배치할 공간이 있어야 한다. 첫 검증은 단일 AZ도 가능하지만 이중화는 아니다. |
| 외부 통신 경로 | NAT/proxy 또는 사전 설치 AMI, S3 gateway endpoint | Elastic·Ubuntu 패키지 다운로드에는 인터넷/NAT/proxy 또는 내부 저장소가 필요하다. AWS endpoint만으로 외부 패키지 저장소에 도달하지는 못한다. |
| 관리 접속 | EC2 SSM Agent 상태, SSM instance profile, 운영자 Session Manager 권한 | public IP·인터넷 SSH 개방 없이 세 EC2를 관리하고 Kibana를 포트 포워딩한다. |
| AMI·EC2·EBS | Ubuntu 24.04 x86_64 AMI, 선택한 instance type 가용성, EBS gp3 용량·암호화 키 | AMI 리전과 아키텍처를 맞춘다. Elasticsearch 용량은 테스트 로그량을 측정한 뒤 조정한다. |
| 기존 업무 서버 | instance ID, OS, CloudWatch Agent 설치/설정 소유자, 실제 로그 파일 경로 | Ubuntu의 모든 환경에 `/var/log/syslog`나 `/var/log/auth.log`가 있다고 가정하지 않는다. journald만 존재하면 먼저 파일 출력 경로를 마련한다. |
| CloudWatch Logs | 업무/Agent/WAF log group 이름, log class, retention, KMS 키, 구독 목록 | 새 Firehose 구독을 추가할 수 있는지 **현재 계정·리전 quota와 기존 사용량**으로 확인한다. 기존 normalizer 구독을 지우지 않는다. |
| WAF | Web ACL ARN, scope, 연결 ALB/CloudFront ARN, 현 로깅 목적지 | 이 예제는 ALB에 연결된 `REGIONAL` WAF이다. CloudFront WAF는 `CLOUDFRONT` scope와 us-east-1 제어면을 별도 설계해야 한다. |
| CloudTrail | trail ARN, home region, 조직 trail 여부, S3 bucket/prefix, event selector, 상태 | 이미 필요한 이벤트를 수집하는 trail이 있으면 재사용한다. Event history만 보는 상태는 이 S3 파이프라인이 아니다. |
| GuardDuty | 현재 리전 detector ID, 관리자 계정, 활성 보호 기능, S3 export 설정 | 기존 detector는 재사용한다. Findings가 수집 대상이며, GuardDuty가 분석한 원시 VPC/DNS 로그 자체가 자동 제공되지는 않는다. |
| 원본 S3 | 기존 사용 여부, bucket region, object prefix, KMS ARN, 버킷 정책, notification 전체 설정 | 기존 CloudTrail 버킷을 사용할 때 기존 알림·정책을 보존할 소유자를 정한다. 새 전용 버킷은 충돌 범위를 줄인다. |
| 스냅샷 S3 | 별도 bucket/prefix, 암호화 키, ES role 접근 | 원본 수집 권한과 인덱스 백업 쓰기 권한을 분리한다. |
| SQS | main queue와 DLQ URL/ARN, 암호화, retention, visibility timeout, redrive policy | S3와 queue는 같은 리전에 둔다. S3 직접 알림에는 Standard queue를 사용한다. |
| 인증서·이름 | EC2 private DNS/IP, Elasticsearch/Kibana 서버 인증서 SAN, 신뢰 CA | 실제 접속 이름이 인증서 SAN에 들어가야 한다. SSM 터널의 로컬 접속 이름도 검증 방법을 정한다. |
| 보관·비용 | S3 원본/비현재 버전, Elasticsearch, CWL 각각의 보관 기간, 비용 알림 수신자 | “한 달”은 프로젝트 가정으로 명시한다. 버전 관리된 객체의 delete marker만으로 과거 버전 저장료가 없어지지는 않는다. |

S3 gateway endpoint는 NAT를 거치는 S3 데이터 전송을 줄이는 데 유용하다. endpoint 정책도 원본·스냅샷·SSM 설치에 필요한 버킷을 허용해야 한다. SSM을 인터넷 없이 사용하려면 대상 리전·Agent 버전에 맞는 `ssm`/`ssmmessages` 등 endpoint와 private DNS, endpoint 보안 그룹의 443 허용을 검토한다. SQS·CloudWatch Logs·KMS API를 직접 호출하는 경로에는 각각의 endpoint 또는 NAT가 필요하다. S3 SSE-KMS 객체 읽기는 S3가 KMS와 연동하므로 모든 경우에 EC2→KMS 직접 연결이 필요한 것은 아니다. [SSM의 VPC endpoint 구성](https://docs.aws.amazon.com/systems-manager/latest/userguide/setup-create-vpc.html)

## 2. 이 저장소의 기존 구성 연결 맵

아래는 이 가이드를 추가하는 기준 커밋 `0fa6761a343d937d3b146efa0f6f0aec5df5475d`의 **파일 내용 기준 연결 맵**이다. 경로는 저장소 루트 기준이다. 실제 배포 환경과 backend/state 소유자는 별도로 확인한다. ELK는 `observability/elk/terraform`에서 독립 실행하며 기존 환경 파일은 수정하지 않는다.

| 저장소 위치 | 파일에서 확인한 정의 | 새 ELK 구성과 연결할 때의 판단 |
|---|---|---|
| `envs/before`, `envs/after` | VPC·업무 EC2·ALB/WAF·S3 endpoint 모듈 조합 | 실제 배포한 환경 하나의 VPC/private subnet/route table을 조회해 새 스택 입력으로 사용한다. ELK 추가를 위해 두 환경을 다시 배포할 필요는 없다. |
| `modules/vpc/main.tf`, `modules/vpc/outputs.tf` | private subnet, private route table, NAT gateway 및 관련 outputs | 실제 subnet과 VPC의 연결 및 NAT 경로를 확인한다. 모듈 출력이 있지만 현재 `envs/after` 루트에는 이를 재노출하는 output이 없으므로, 루트 `terraform output`만으로 조회된다고 가정하지 않는다. |
| `modules/alb-waf/main.tf` | WAF→CWL logging configuration, `aws-waf-logs-cloud9-security` log group, 3일 retention | 기존 그룹을 `existing_log_group_names.waf`에 입력하고 `manage_waf_logging=false`를 유지한다. 새 ELK 스택은 구독을 추가하며 WAF 목적지·retention 변경은 기존 소유 스택에서 수행한다. |
| `modules/ec2`, `modules/iam` | 업무 EC2·instance profile·S3 접근 역할 | 로그 플랫폼용 EC2와 구분한다. 업무 서버의 Agent 유무·실제 로그 파일·SSM 및 전송 권한은 배포 계정에서 확인하고, 기존 역할 변경은 기존 소유 코드에서 검토한다. |
| `modules/s3-endpoint/main.tf`의 공격 실습 버킷 정책 | 특정 VPC endpoint 외 요청을 거부하는 `aws:sourceVpce` 조건 | 공격 실습용 버킷과 로그 보관 버킷은 용도가 다르다. 이 Deny 정책을 원본 버킷에 그대로 복사하면 CloudTrail·Firehose·GuardDuty 서비스 전달을 차단할 수 있다. |

이 기준 커밋에는 CloudTrail·GuardDuty·CloudWatch Agent를 묶어 관리하는 별도 모듈이 없다. 계정·조직 또는 다른 저장소에서 이미 관리할 수 있으므로 AWS에서 실제 자원을 먼저 조회한다. 기존 Trail·detector·Agent 설정이 있다면 소유자가 관리하는 경로를 유지하고, 기존 CWL 구독이나 S3 notification을 새 ELK 연결로 통째로 교체하지 않는다. CloudTrail을 S3와 CWL 양쪽에서 동시에 색인하지 않는지도 확인한다.

`modules/s3-endpoint`가 배포된 VPC라면 기존 S3 gateway endpoint와 정책을 확인하고 `create_s3_gateway_endpoint=false`를 유지한다. ELK용 state는 `envs/after/terraform.tfstate` 같은 기존 환경 key와 분리한다. 같은 상태 버킷을 허용 범위 안에서 공유하더라도 ELK 전용 key와 잠금 권한은 별도로 확인한다.

**자원별 소유권 원칙:** 기존 리소스의 ARN/ID를 입력으로 참조하는 것과 해당 리소스를 Terraform `resource`로 관리하는 것은 다르다. 기존 자원을 이 스택에 옮길 계획이 없다면 import하지 않는다. 이관이 필요하면 기존 owner에서 state 이동·삭제 계획까지 함께 정리한다.

특히 `aws_s3_bucket_notification`은 버킷의 알림 구성을 하나의 단위로 관리한다. prefix마다 리소스를 따로 정의해서 공유하면 서로 덮어쓸 수 있다. 이미 알림이 있으면 기존 owner가 **전체 기존 설정에 새 queue 항목을 병합**하도록 한다. S3 알림은 중복 전달과 순서 변경이 가능하므로 문서 ID 기반 중복 처리도 별도로 필요하다. [Terraform S3 notification](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_notification), [S3 알림 목적지·전달 특성](https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html)

## 3. 읽기 전용 AWS CLI 확인 예제 — PowerShell

다음은 **사용자가 Windows 로컬 PowerShell에서 자원을 확인할 때 실행할 예제**다. 패키지의 다른 문서에 있는 `bash` 블록은 CloudShell/Linux용이고, 여기의 `powershell` 블록과 혼용하지 않는다. 이 가이드 제작 과정에서는 실행하지 않았다. 먼저 AWS CLI v2와 사용하는 profile의 로그인이 준비되어 있어야 한다. ID/이름은 예시를 실제값으로 교체하고, 조회 권한이 없는 명령은 담당자에게 해당 항목만 확인받는다. Access key, 비밀번호, 토큰을 코드나 출력에 넣지 않는다. 모든 실행 줄 끝의 `#` 뒤는 해당 줄의 주석이다.

### 계정·네트워크·관리 접속

```powershell
$elkProfile = 'YOUR_PROFILE' # 이미 로그인한 AWS CLI profile 이름으로 교체한다.
$elkRegion = 'ap-northeast-2' # 첫 검증의 리전 예시이며 실제 대상 리전으로 교체한다.
$elkVpcId = 'vpc-REPLACE_ME' # 기존 VPC의 실제 ID로 교체한다.
aws sts get-caller-identity --profile $elkProfile --region $elkRegion --no-cli-pager # 계정 ID와 현재 역할 ARN만 확인한다.
aws ec2 describe-vpcs --vpc-ids $elkVpcId --profile $elkProfile --region $elkRegion --query 'Vpcs[].{ID:VpcId,CIDR:CidrBlock,State:State}' --no-cli-pager # VPC의 존재·CIDR·상태를 확인한다.
aws ec2 describe-vpc-attribute --vpc-id $elkVpcId --attribute enableDnsSupport --profile $elkProfile --region $elkRegion --no-cli-pager # VPC DNS 해석 기능을 확인한다.
aws ec2 describe-vpc-attribute --vpc-id $elkVpcId --attribute enableDnsHostnames --profile $elkProfile --region $elkRegion --no-cli-pager # private DNS 사용에 필요한 이름 설정을 확인한다.
aws ec2 describe-subnets --filters "Name=vpc-id,Values=$elkVpcId" --profile $elkProfile --region $elkRegion --query 'Subnets[].{ID:SubnetId,AZ:AvailabilityZone,CIDR:CidrBlock,Free:AvailableIpAddressCount,PublicIP:MapPublicIpOnLaunch}' --no-cli-pager # subnet과 남은 IP를 확인하고 private subnet을 선정한다.
aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$elkVpcId" --profile $elkProfile --region $elkRegion --query 'RouteTables[].{ID:RouteTableId,Associations:Associations,Routes:Routes}' --no-cli-pager # 실제 subnet 연결 및 NAT·S3 endpoint 경로를 확인한다.
aws ec2 describe-nat-gateways --filter "Name=vpc-id,Values=$elkVpcId" --profile $elkProfile --region $elkRegion --query 'NatGateways[].{ID:NatGatewayId,State:State,Subnet:SubnetId}' --no-cli-pager # NAT가 필요한 구성이라면 available 상태인지 확인한다.
aws ec2 describe-vpc-endpoints --filters "Name=vpc-id,Values=$elkVpcId" --profile $elkProfile --region $elkRegion --query 'VpcEndpoints[].{ID:VpcEndpointId,Service:ServiceName,State:State,PrivateDNS:PrivateDnsEnabled,RouteTables:RouteTableIds,Subnets:SubnetIds}' --no-cli-pager # S3·SSM·SQS 등 기존 endpoint를 확인한다.
aws ec2 describe-instances --filters "Name=vpc-id,Values=$elkVpcId" "Name=instance-state-name,Values=pending,running,stopping,stopped" --profile $elkProfile --region $elkRegion --query 'Reservations[].Instances[].{ID:InstanceId,IP:PrivateIpAddress,Subnet:SubnetId,Profile:IamInstanceProfile.Arn,State:State.Name}' --no-cli-pager # 업무 서버와 신규 로그 서버를 구분할 수 있는 메타데이터만 조회한다.
aws ssm describe-instance-information --profile $elkProfile --region $elkRegion --query 'InstanceInformationList[].{ID:InstanceId,Ping:PingStatus,OS:PlatformName,Agent:AgentVersion}' --no-cli-pager # 관리할 인스턴스의 SSM 등록·Online 상태를 확인한다.
```

### 로그 소스와 기존 구독

```powershell
$elkLogGroup = '/REPLACE_WITH_EXISTING_APP_LOG_GROUP' # 실제 업무 로그 그룹 이름으로 교체한다.
$elkWafArn = 'arn:aws:wafv2:ap-northeast-2:123456789012:regional/webacl/REPLACE/REPLACE' # 확인한 REGIONAL Web ACL ARN으로 교체한다.
aws logs describe-log-groups --log-group-name-prefix $elkLogGroup --profile $elkProfile --region $elkRegion --query 'logGroups[].{Name:logGroupName,Class:logGroupClass,Retention:retentionInDays,KMS:kmsKeyId}' --no-cli-pager # 그룹의 존재·보관·암호화 설정을 확인한다.
aws logs describe-subscription-filters --log-group-name $elkLogGroup --profile $elkProfile --region $elkRegion --no-cli-pager # 기존 destination과 filter를 확인하여 새 구독이 덮어쓰지 않게 한다.
aws logs describe-account-policies --policy-type SUBSCRIPTION_FILTER_POLICY --profile $elkProfile --region $elkRegion --no-cli-pager # 계정 단위 구독 정책이 이미 전달을 수행하는지도 확인한다.
aws service-quotas list-service-quotas --service-code logs --profile $elkProfile --region $elkRegion --query 'Quotas[].{Name:QuotaName,Value:Value,Adjustable:Adjustable}' --no-cli-pager # 조회 가능한 현재 CWL quota를 확인하고 비노출 고정 quota는 공식 문서와 함께 확인한다.
aws wafv2 get-logging-configuration --resource-arn $elkWafArn --profile $elkProfile --region $elkRegion --no-cli-pager # WAF의 현 목적지·KEEP/DROP·redaction 설정을 확인한다.
aws cloudtrail describe-trails --include-shadow-trails --profile $elkProfile --region $elkRegion --query 'trailList[].{Name:Name,ARN:TrailARN,Home:HomeRegion,Bucket:S3BucketName,Prefix:S3KeyPrefix,Org:IsOrganizationTrail,Multi:IsMultiRegionTrail}' --no-cli-pager # 조직·다른 리전 trail을 포함하여 중복 생성 여부를 판단한다.
$elkTrailArn = 'arn:aws:cloudtrail:ap-northeast-2:123456789012:trail/REPLACE' # 사용할 기존 trail ARN으로 교체한다.
$elkTrailHomeRegion = 'ap-northeast-2' # 위에서 확인한 trail의 실제 home region으로 교체한다.
aws cloudtrail get-trail-status --name $elkTrailArn --profile $elkProfile --region $elkTrailHomeRegion --no-cli-pager # Logging 상태·최근 S3 전달·전달 오류를 확인한다.
aws cloudtrail get-event-selectors --trail-name $elkTrailArn --profile $elkProfile --region $elkTrailHomeRegion --no-cli-pager # 관리/데이터 이벤트 범위가 테스트 목적과 일치하는지 확인한다.
aws guardduty list-detectors --profile $elkProfile --region $elkRegion --no-cli-pager # 이 계정·리전의 detector를 먼저 조회한다.
$elkDetectorId = 'REPLACE_WITH_DETECTOR_ID' # 조회된 기존 detector ID로 교체하며 없으면 다음 두 줄은 건너뛴다.
aws guardduty get-detector --detector-id $elkDetectorId --profile $elkProfile --region $elkRegion --no-cli-pager # 활성 상태·보호 기능·Finding 갱신 주기를 확인한다.
aws guardduty list-publishing-destinations --detector-id $elkDetectorId --profile $elkProfile --region $elkRegion --no-cli-pager # 기존 S3 export가 이미 존재하는지 확인한다.
```

CLI가 오래되어 account policy·quota 조회 옵션을 지원하지 않으면 CLI v2를 업데이트하거나 콘솔에서 같은 항목을 확인한다. 구독이 꽉 찼을 때 기존 대응 Lambda를 임의로 삭제하는 대신 기존 수집 경로에서 분기하거나 전달 경로를 재설계한다.

### S3·KMS·SQS 설정

```powershell
$elkRawBucket = 'REPLACE-WITH-EXISTING-RAW-BUCKET' # 재사용할 버킷만 입력하며 새 버킷이면 생성 뒤 실행한다.
aws s3api get-bucket-location --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 원본 버킷 리전을 확인한다.
aws s3api get-public-access-block --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 공개 접근 차단 설정을 확인한다.
aws s3api get-bucket-encryption --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 기본 암호화 방식과 KMS 키 식별자를 확인한다.
aws s3api get-bucket-versioning --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 버전 관리 상태를 확인한다.
aws s3api get-bucket-lifecycle-configuration --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 원본·비현재 버전이 언제 만료되는지 확인한다.
aws s3api get-bucket-notification-configuration --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # SQS·SNS·Lambda·EventBridge 기존 설정을 모두 확인한다.
aws s3api get-bucket-policy --bucket $elkRawBucket --profile $elkProfile --region $elkRegion --no-cli-pager # 전달 서비스·읽기 역할·명시적 Deny의 충돌 여부를 확인한다.
$elkKmsKeyArn = 'arn:aws:kms:ap-northeast-2:123456789012:key/REPLACE' # 실제 암호화 키 ARN으로 교체한다.
aws kms describe-key --key-id $elkKmsKeyArn --profile $elkProfile --region $elkRegion --query 'KeyMetadata.{ARN:Arn,State:KeyState,Usage:KeyUsage,Manager:KeyManager}' --no-cli-pager # 키 활성·대칭 암호화 용도·관리 주체를 확인한다.
aws kms get-key-policy --key-id $elkKmsKeyArn --policy-name default --profile $elkProfile --region $elkRegion --no-cli-pager # 키 자체의 정책이 IAM 정책과 함께 필요한 사용자를 허용하는지 확인한다.
$elkQueueUrl = 'https://sqs.ap-northeast-2.amazonaws.com/123456789012/REPLACE' # 실제 수집용 queue URL로 교체한다.
aws sqs get-queue-attributes --queue-url $elkQueueUrl --attribute-names QueueArn VisibilityTimeout MessageRetentionPeriod RedrivePolicy Policy SqsManagedSseEnabled KmsMasterKeyId ApproximateNumberOfMessages --profile $elkProfile --region $elkRegion --no-cli-pager # queue 정책·암호화·재시도·현재 적체를 조회하며 메시지를 소비하지 않는다.
```

없는 lifecycle·bucket policy 등을 읽으면 `NoSuch...` 오류가 날 수 있다. 이는 해당 설정이 없다는 확인 결과이며 곧바로 자원 전체가 없다는 뜻은 아니다. 조회 출력에는 내부 ARN·정책·경로가 포함될 수 있으므로 공개 저장소에 그대로 올리지 않는다.

## 4. 실행 가능 판정

- [ ] 계정·리전·VPC와 세 EC2 subnet을 실제 조회로 확인했다.
- [ ] 기존 trail/detector/WAF logging/Agent 설정의 owner가 확정되었다.
- [ ] source log group별 새 구독을 추가할 수 있고 기존 계정 구독과 중복되지 않는다.
- [ ] S3 notification·bucket policy·KMS key policy의 전체 설정을 관리할 owner가 정해졌다.
- [ ] NAT/proxy/내부 저장소 중 패키지 설치 경로와 AWS API 통신 경로가 존재한다.
- [ ] S3 원본 버킷은 EC2 3대와 수명 주기가 분리되고 수집 role에 삭제 권한이 없다.
- [ ] S3·CWL·ES의 보관 기간과 예상 로그량·비용 기준이 정해졌다.
- [ ] plan에서 기존 업무 자원의 삭제·교체·WAF rule 변경·기존 구독 삭제가 발생하지 않는다.

이 조건이 충족되면 [AWS 콘솔 구축 순서](aws-console-guide.md)와 상위 가이드의 Terraform 실행 순서로 진행한다. 새 업무 서버의 파일 로그 연결은 [CloudWatch Agent 설치·설정 가이드](cloudwatch-agent-guide.md)를 사용한다.
