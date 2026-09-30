# WHS 취약 웹앱 공격 툴 — 인수인계

## 0. 현재 상태

- **코드는 전부 작성됨**: `common.py`, `payloads/`, `scenario1~3` 모두 구현 완료.
  수정 이력과 판단 근거는 [CHANGES.md](CHANGES.md), 사용법·원상복구는 [README.md](README.md).
- 목적은 "완벽한 공격"이 아니라 **탐지 이벤트를 확실히·안전하게 발생시키는 틀**.
- 실제 공격 실행은 사용자가 직접 한다.

> **자격증명 주의**: 로그인 계정·키 등 실제 값은 각 시나리오의 `.env` 에만 넣는다.
> 이 문서와 `.env.example` 에는 절대 적지 않는다(둘 다 커밋되는 파일).

## 1. 대상

- 웹앱: WHS-Cloud9-Vuln-Web (Node/Express). https://whs4namu.click
- 소스: https://github.com/yunduhyun/WHS-Vuln-Web
- 계정 896986966760 / ap-northeast-2. ALB 뒤 EC2 **2대**(라운드로빈).
- 정상 로그인 계정: `scenario1/.env`, `scenario3/.env` 의 `WHS_LOGIN_EMAIL` / `WHS_LOGIN_PASSWORD` 참조.
- 인프라는 전부 "취약한 상태 그대로"(IMDSv1, VPC endpoint 비강제, WAF 비차단). RDS·S3 연결 완료.

## 2. 웹앱 취약점 5종 (전부 `/api/*` 인증 뒤, 세션 필요)

- 필수: 모든 non-GET 에 헤더 `X-WHS-Request: 1` 없으면 403 (CSRF 방어).
- 1. **SQLi**: `POST /api/login` → login.js 가 email 을 쿼리에 직접 삽입.
  `' OR '1'='1' -- ` 로 인증 우회(비번 조건 주석처리, `LIMIT 1` 첫 행 반환).
- 2. **SSRF**: `POST /api/images/preview {url}` → 검증 없음. 이미지가 아니면 응답 원문을
  `text` 필드에 16000자 반환. GET 전용(fetch).
- 3. **SSTI**: `POST /api/labs/ssti {template}` → `ejs.render` 직결.
  앱이 **ESM** 이라 `require` 와 `process.mainModule` 이 둘 다 `undefined` 다.
  흔히 쓰는 `mainModule.require('child_process')` 페이로드는 통하지 않는다.
  실측으로 동작하는 가젯은 `process.binding('spawn_sync').spawn(...)` (2026-09-29 확인).
  전역에 `awslambda` 가 남아 있으나 Lambda 배포 시절 잔재이고, 도메인은 ALB→EC2 로 간다.
- 4. **OS 커맨드**: `POST /api/labs/os-command {input}` → `/bin/sh -c "printf '%s\n' <input>"`.
  페이로드 `x; <cmd>` 로 임의 실행. **제한 200자**/8초/32KB → 긴 스크립트는 5번 경로를 쓴다.
- 5. **업로드→실행**: `POST /api/files` (multipart) → S3 저장 → `POST /api/files/execute {key}`
  로 `.js/.py/.sh` 실행. 5MB/8초. **S3에 남으므로 어느 인스턴스든 재실행 = stateless 웹셸.**

## 3. 정찰로 실측 확정된 사실

- **IMDSv1 열림**: SSRF로 `http://169.254.169.254/...` 평문 응답 OK → 시나리오1 성립.
- EC2 role: `cloud9-infra-attack-ec2-role` (프로파일 `whs-project/cloud9-infra-attack-ec2-profile`).
- 인스턴스: `i-09376e26a25dd5b89` / `i-074bd46789ad0b962`, t3.micro, AL2023,
  privateIp 10.3.11.50 & 10.3.12.232.
- 실행계정 ec2-user(wheel), 앱경로 `/home/ec2-user/WHS-Vuln-Web`, node v22, python3·curl·aws-cli 있음.
- 아웃바운드 인터넷 개방(NAT 공인IP 3.39.5.139). 마이닝풀 DNS 해석됨(pool.supportxmr.com→141.94.96.x).
- 쓰기: `/tmp` OK, `/opt` 는 root 소유 불가, `~ec2-user` OK. crontab 없음, systemctl 있음.
- SSH: private subnet, 공인IP 없음 → T1133 실제재현 불가(연결 시도만, 흐름도 유지).
- **VPC endpoint 는 강제(Deny)가 아님** → 탈취한 임시키를 로컬 boto3 로 그대로 사용.
  (이 확인으로 scenario1 의 `--exec-on local|ec2` 이중 경로를 제거했다.)

### role 실효 권한 (RCE로 aws-cli 실행해 확인)

- 허용: `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`(계정 14개 버킷 노출), `s3:ListBucket`,
  `s3:GetObject`, `ec2:DescribeInstances`, `cloudtrail:DescribeTrails`,
  `secretsmanager:ListSecrets`, `rds:DescribeDBInstances`, `guardduty:ListDetectors`,
  `s3:GetBucketVersioning`. (ReadOnlyAccess 광범위 허용)
- 거부: **`iam:*` → 권한경계 `WHSProjectRoleBoundary` 가 명시적 Deny.**
  **`s3:PutObject` / `s3:DeleteObject` → `whs-data/` 에서 Deny** (앱 업로드는 `whs-uploads/` 만 허용 추정).
  → 이 Deny 들은 버그가 아니라 **CloudTrail 탐지 증거**다. 코드가 `expect=(DENY,)` 로 통과시킨다.
- GuardDuty Detector ID: `2daa4601845647bc8ea3e66f821d8401`.
- 버킷: `whs-cloud9-vuln-web-lab-896986966760-ap-northeast-2-an` (앱 업로드, `whs-uploads/`),
  `cloud9-attack-target-a396cc5b` (구 데이터버킷),
  `cloud9-attack-profile-a396cc5b`, `cloud9-security-*-cloudtrail`, `whs-elk-*` 등.
- 시크릿: `VulnWeb-DB-env`. RDS: `whs-cloud9-vulnweb-db.c92aiqeucjlz.ap-northeast-2.rds.amazonaws.com`

## 4. 남은 미결정 사항

1. **`vulnEC2_Policy` / `cloud9-infra-attack-s3-access` 정책 JSON** — `PutObject` 정확한 허용 범위.
2. **SSE-C 랜섬 대상 위치** — 사용자가 EC2 role 에 해당 권한을 부여해 `whs-data/` 에서
   실제 재암호화가 되도록 할 예정. 부여 전에는 `--ransom` 이 AccessDenied 로깅만 남긴다
   (코드는 양쪽 다 처리함 — 차단되면 증거로 기록하고 계속).
3. **더미 데이터** — `customers.csv`/`config.json`/`flag.txt` 를 `whs-data/` 에 새로 심을지,
   구 버킷(`cloud9-attack-target-a396cc5b`) 을 재사용할지.
   (코드는 `NoSuchKey` 를 예상된 결과로 처리하므로 미설치 상태에서도 돈다.)

## 5. 다음 할 일

1. `--ransom` 을 쓸 버킷/prefix 에 `s3:PutObject` 권한 부여 (위 4-2).
2. `whs-data/` 에 더미 데이터 심기 (위 4-3).
3. 시나리오 1→2→3 순차 실행 후 탐지 측(GuardDuty/CloudTrail/Flow Log/ELK)에서 이벤트 확인.
4. **실습 후 [README.md](README.md) 의 "원상복구 절차" 전부 수행** —
   특히 GuardDuty 재활성화와 `--restore`.
