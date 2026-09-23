# 입력 형식 검증용 샘플

이 폴더의 JSON과 gzip은 `tools/make_samples.py`가 생성한 가상 데이터다. 계정 번호 `123456789012`, `i-EXAMPLE`, 문서용 IP `192.0.2.0/24`는 실제 자원을 가리키지 않는다. AWS에서 전달을 검증한 결과물도 아니다.

| 샘플 | S3 파일 내부 형식 | 대조 식별자 |
|---|---|---|
| cloudtrail.json.gz | `Records` 배열을 가진 JSON | `00000000-0000-4000-8000-000000000001` |
| cloudwatch.json.gz | `logEvents`를 가진 CloudWatch envelope JSONL | `cw-sample-001`, `ELK_VALIDATION_MARKER` |
| waf.json.gz | CloudWatch envelope 안 `message`에 WAF JSON 문자열 | `cw-waf-sample-001`, `waf-sample-001` |
| guardduty.json.gz | Finding 객체 JSONL | `00000000000000000000000000000003` |
| cloudwatch-control.json.gz | 빈 CloudWatch 제어 메시지 | 업무 이벤트를 새로 만들면 안 됨 |
| malformed.json.txt | 의도적으로 깨진 JSON | 별도 실패 격리 경로 시험 |

샘플 발생 시각은 **2026-09-16 UTC**로 고정했다. Kibana 시간 범위를 해당 날짜로 바꾸지 않으면 정상 색인돼도 화면에서 보이지 않을 수 있다. 실제 구축일 검증에는 고유 식별자와 현재 시각을 가진 새 표본도 생성한다.

```bash
python3 tools/make_samples.py # 저장된 샘플을 같은 내용으로 다시 생성한다.
gzip -t samples/cloudtrail.json.gz # gzip 자체가 손상되지 않았는지 검사한다.
gzip -dc samples/cloudtrail.json.gz | python3 -m json.tool # 압축을 풀어 표준 JSON 파서로 형식을 확인한다.
```

실제 AWS 원본 전달을 확인하는 검증과 수동 샘플 업로드 검증을 구분한다. 수동 업로드는 **S3 이후 수집 경로**만 증명한다. CloudTrail·WAF·CloudWatch Agent·GuardDuty가 실제로 로그를 전달하는지는 별도 서비스 이벤트로 확인해야 한다.

오류 샘플을 원본 감사 경로에 무작정 업로드하지 않는다. 검증용 prefix나 임시 큐에서 시험하고, 어떤 파일이 사람이 넣은 테스트 데이터인지 결과표에 기록한다. 스냅샷 저장소와 배포 파일 저장소는 수집 알림 대상이 아니다.
