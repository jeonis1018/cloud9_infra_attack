#!/bin/sh
# persist.sh — scenario2 3단계 웹셸 지속성 마커 (T1505.003 Web Shell)
#
# 이 스크립트가 S3(whs-uploads/)에 남는 것 자체가 지속성이다. 앱이
# POST /api/files/execute {key} 로 받아 실행하므로 업로드 한 번이면 재호출된다.
#
# 실제 페이로드는 심지 않는다. 재호출 여부와 도달한 인스턴스만 증거로 남기고
# 호스트 상태는 바꾸지 않는다.
# 출력 첫 줄은 hostname 이어야 한다. run_payload_on_target 이 인스턴스 식별에 쓴다.
hostname

# 고정된 대상이 아니면 빠진다. ALB 라운드로빈으로 다른 인스턴스에 닿으면 흔적을 남기지 않는다.
case $(hostname) in
  @@TARGET@@.*) ;;
  *) echo "__MISS__"; exit 0 ;;
esac

echo "marker=@@MARKER@@"
echo "runid=@@RUN_ID@@"
id
date -u +%Y-%m-%dT%H:%M:%SZ
