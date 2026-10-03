#!/bin/sh
# dnscheck.sh — DNS 송신 통제 검증 프로브 (Route 53 Resolver DNS Firewall)
#
# VPC 안에서 나가는 이름 질의가 DNS Firewall 에 걸리는지 확인한다.
# 질의를 한 번 보내고 결과만 찍는다. 데이터를 보내지 않고 상태도 바꾸지 않는다.
#
# 같은 스크립트를 세 번 돌려서 before/after 를 만드는 것이 용도다.
#   1) 규칙 없음   → RESOLVE OK      쿼리 로그에 firewall_rule_action 없음
#   2) ALERT       → RESOLVE OK      쿼리 로그에 ALERT
#   3) BLOCK       → RESOLVE FAILED  쿼리 로그에 BLOCK
#
# 코드는 그대로 두고 방어 설정만 바꿔서 결과가 뒤집히는 것을 보여준다.
#
# 출력 첫 줄은 hostname 이어야 한다. run_payload_on_target 이 인스턴스 식별에 쓴다.
hostname

# 고정된 대상이 아니면 빠진다. 질의가 다른 인스턴스에서 나가면
# 쿼리 로그의 srcaddr 이 달라져 증거를 맞추기 어렵다.
case $(hostname) in
  @@TARGET@@.*) ;;
  *) echo "__MISS__"; exit 0 ;;
esac

DOMAIN="@@DOMAIN@@"
RUN_ID="@@RUN_ID@@"

echo "DNSCHECK_BEGIN runid=$RUN_ID domain=$DOMAIN"

# 어느 리졸버로 나가는지. VPC 리졸버(.2)가 아니면 DNS Firewall 이 평가하지 않으므로
# 결과 해석이 달라진다. 그래서 질의 결과와 같은 출력에 남긴다.
echo "RESOLVER $(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf)"

# 이름 해석 한 번. getent 는 NSS 를 타므로 /etc/resolv.conf 의 리졸버로 나간다.
R=$(getent hosts "$DOMAIN" 2>/dev/null | head -1)
if [ -n "$R" ]; then
  echo "RESOLVE OK $R"
else
  echo "RESOLVE FAILED"
fi

echo "DNSCHECK_END"
