#!/usr/bin/env bash
set -euo pipefail # 오류와 미정의 변수, 파이프 오류가 있으면 즉시 중단합니다.
umask 027 # 새 설정 파일은 기본적으로 다른 사용자에게 공개하지 않습니다.
[[ ${EUID} -eq 0 ]] || { echo 'sudo bash 00-install.sh ROLE 로 실행하세요.' >&2; exit 1; } # 패키지 설치 권한을 확인합니다.
ROLE=${1:?collector, elasticsearch, kibana 중 하나가 필요합니다.} # 설치할 EC2 역할을 받습니다.
VERSION=9.5.3 # 검증 대상 버전을 고정하며 임의의 최신 버전을 설치하지 않습니다.
case "$ROLE" in collector) PACKAGES=(filebeat logstash);; elasticsearch) PACKAGES=(elasticsearch);; kibana) PACKAGES=(kibana);; *) exit 2;; esac # 역할에 필요한 패키지만 선택합니다.
. /etc/os-release # OS 공급자와 버전 정보를 읽습니다.
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 && $(dpkg --print-architecture) == amd64 ]] || { echo 'Ubuntu 24.04 amd64 전용입니다.' >&2; exit 1; } # 재현할 환경을 제한합니다.
apt-get update # Ubuntu 패키지 목록을 갱신합니다.
apt-get install -y ca-certificates curl gnupg python3 openssl unzip # TLS, 서명 검증, 설정 생성 도구를 설치합니다.
WORK=$(mktemp -d) # 다운로드할 공개 서명키의 임시 경로를 만듭니다.
trap 'rm -rf -- "$WORK"' EXIT # 이 스크립트가 직접 만든 임시 폴더만 정리합니다.
curl --fail --silent --show-error --location https://artifacts.elastic.co/GPG-KEY-elasticsearch -o "$WORK/elastic.asc" # 공식 HTTPS 주소의 공개 서명키를 받습니다.
FINGERPRINT=$(gpg --show-keys --with-colons "$WORK/elastic.asc" | awk -F: '$1 == "fpr" {print $10; exit}') # 공개키의 전체 fingerprint를 추출합니다.
[[ "$FINGERPRINT" == 46095ACC8548582C1A2699A9D27D666CD88E42B4 ]] || { echo 'Elastic signing key 불일치' >&2; exit 1; } # 공식 문서의 서명키와 일치해야 진행합니다.
gpg --batch --yes --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg "$WORK/elastic.asc" # apt가 검증할 키링을 만듭니다.
chmod 0644 /usr/share/keyrings/elasticsearch-keyring.gpg # apt 비특권 프로세스가 공개키를 읽게 합니다.
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main' > /etc/apt/sources.list.d/elastic-9.x.list # 9.x 공식 저장소를 등록합니다.
apt-get update # Elastic 패키지 목록을 갱신합니다.
for PACKAGE in "${PACKAGES[@]}"; do # 필요한 구성 요소를 하나씩 설치합니다.
  apt-cache show "$PACKAGE=$VERSION" >/dev/null || { echo "$PACKAGE=$VERSION 패키지가 없습니다. 자동 대체하지 않습니다." >&2; exit 1; } # 배포 시점의 실제 패키지 존재를 검사합니다.
  DEBIAN_FRONTEND=noninteractive apt-get install -y "$PACKAGE=$VERSION" # 동일 버전의 서명된 Debian 패키지를 설치합니다.
  systemctl stop "$PACKAGE" # 인증서와 설정을 넣기 전에는 서비스를 중지합니다.
  apt-mark hold "$PACKAGE" # 무심코 실행한 apt upgrade로 버전이 달라지는 것을 막습니다.
done # 역할별 패키지 설치를 마칩니다.
echo '설치 완료. 다음은 인증서 배치 및 20-configure.py입니다.' # 다음 수동 단계를 안내합니다.
