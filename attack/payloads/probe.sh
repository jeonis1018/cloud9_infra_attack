#!/bin/sh
# probe.sh — 실행 컨텍스트 정찰 (MITRE T1082 System Information Discovery)
#
# scenario2 2단계 업로드→실행 경로로 코드가 실제 돌았는지 확인한다.
# 상태를 바꾸지 않는 읽기 전용 페이로드.
# 출력 첫 줄은 hostname 이어야 한다. run_payload_on_target 이 인스턴스 식별에 쓴다.
hostname

# 고정된 대상이 아니면 빠진다. 읽기 전용이지만 다른 페이로드와 형태를 맞춘다.
case $(hostname) in
  @@TARGET@@.*) ;;
  *) echo "__MISS__"; exit 0 ;;
esac

id
uname -sr
pwd
