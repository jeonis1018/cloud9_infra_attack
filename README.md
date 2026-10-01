# [WHS4기] Cloud9와 4분의 3 승강장에서 널 기다려 / 구축 공격 팀

KISA 화이트햇 스쿨 4기 AWS 보안 아키텍처 팀 프로젝트

SSRF → IMDSv1 → EC2 IAM Role 임시자격증명 탈취 → S3 데이터 유출 공격 체인을
Terraform IaC로 재현하고, 통제 적용 전/후(Before/After) 상태를 비교 시연한다.

로그 수집·검색을 검증하려면 [ELK 구축 가이드](observability/elk/README.md)를 참고한다. 기존 VPC를 재사용하는 독립 스택으로, 수집기·Elasticsearch·Kibana EC2를 각각 한 대씩 구성하며 기존 환경과 별도 Terraform state로 관리한다.
