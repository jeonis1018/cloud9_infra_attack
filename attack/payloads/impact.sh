#!/bin/sh
# impact.sh — scenario3 4단계 호스트 영향 (T1486 Data Encrypted for Impact)
#
# @@DUMMY_DIR@@ 에 이미 있는 파일을 찾아 잠근다. 대상을 직접 만들지 않는다.
# 공격 스크립트가 잠글 대상까지 만들면 "있던 데이터를 암호화했다"가 성립하지 않는다.
# 대상은 인프라 쪽에서 미리 심어 둔다(user_data / AMI). 비어 있으면 NO_TARGETS 로 중단한다.
#
# base64 변형이라 키 없이 되돌아가고, 원본은 .bak 으로 남기며 restore.sh 도 함께 만든다.
# 대상이 /tmp 하위가 아니면 실행을 거부한다. 시스템·앱 파일은 건드리지 않는다.
#
# 출력 첫 줄은 hostname 이어야 한다. run_payload_on_target 이 인스턴스 식별에 쓴다.
hostname

# 고정된 대상이 아니면 빠진다. 파일을 변형하므로 다른 인스턴스에서 돌아선 안 된다.
case $(hostname) in
  @@TARGET@@.*) ;;
  *) echo "__MISS__"; exit 0 ;;
esac

DIR="@@DUMMY_DIR@@"
RUN_ID="@@RUN_ID@@"

# 안전 가드: 실습 더미 경로 하나만 허용한다.
# /opt/* 처럼 넓게 열어두면 경로 오타가 시스템 파일에 닿을 수 있다.
case "$DIR" in
  /opt/whs-lab-data|/opt/whs-lab-data/*) ;;
  *) echo "REFUSED: 허용된 실습 경로가 아님 ($DIR)"; exit 1 ;;
esac

[ -d "$DIR" ] || { echo "NO_TARGETS: $DIR 디렉터리가 없다"; exit 1; }
cd "$DIR" || exit 1

# 잠글 대상 수집. 이 스크립트가 만드는 산출물(.bak/.locked/restore.sh/NOTE.txt)은 제외.
TARGETS=$(ls -1 2>/dev/null | grep -v -e '\.bak$' -e '\.locked$' -e '^restore\.sh$' -e '^NOTE\.txt$')
[ -n "$TARGETS" ] || { echo "NO_TARGETS: $DIR 에 잠글 파일이 없다"; exit 1; }

# 복구 스크립트를 변형 '전에' 먼저 만든다 — 중간에 실패해도 복구 수단이 남도록.
cat > restore.sh <<'EOF'
#!/bin/sh
# restore.sh — impact.sh 변형을 원상복구. base64 디코드 + .bak 검증.
cd "$(dirname "$0")" || exit 1
for f in *.locked; do
  [ -f "$f" ] || continue
  orig="${f%.locked}"
  base64 -d "$f" > "$orig" || { echo "FAILED_DECODE $f"; continue; }
  if [ -f "$orig.bak" ] && cmp -s "$orig" "$orig.bak"; then
    echo "RESTORED_VERIFIED $orig"
  else
    echo "RESTORED_UNVERIFIED $orig"
  fi
  rm -f "$f"
done
EOF
chmod +x restore.sh

echo "MANIFEST_BEGIN runid=$RUN_ID dir=$DIR"
for f in $TARGETS; do
  [ -f "$f" ] || continue
  cp -p "$f" "$f.bak" || continue           # 원본 보존
  base64 "$f.bak" > "$f.locked" || continue # 가역 변형
  rm -f "$f"
  echo "LOCKED $f -> $f.locked (backup: $f.bak)"
done
echo "MANIFEST_END"

cat > NOTE.txt <<EOF
WHS lab impact demo (runid=$RUN_ID).
Reversible: run ./restore.sh in this directory.
Originals preserved as *.bak. No system or application file was touched.
EOF

ls -1
