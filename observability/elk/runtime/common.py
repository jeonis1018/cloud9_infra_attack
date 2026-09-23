#!/usr/bin/env python3
import ipaddress # 설정에 입력한 IP를 검증합니다.
import pathlib # 경로를 안전하게 다룹니다.
import re # 리전과 버킷 이름 형식을 검증합니다.
import shlex # shell을 실행하지 않고 값과 줄 주석만 읽습니다.
from urllib.parse import urlparse # SQS URL의 구조를 검사합니다.
def load_settings(path): # 주석이 있는 비밀정보 없는 env 파일을 읽습니다.
    values = {} # 파싱된 설정을 담습니다.
    for number, line in enumerate(pathlib.Path(path).read_text(encoding="utf-8").splitlines(), 1): # 각 줄에 번호를 붙여 검사합니다.
        words = shlex.split(line, comments=True) # 인라인 주석과 따옴표를 처리합니다.
        if not words: # 빈 줄과 주석만 있는 줄을 건너뜁니다.
            continue # 다음 줄을 읽습니다.
        if len(words) != 1 or "=" not in words[0]: # 복잡한 shell 문장을 허용하지 않습니다.
            raise ValueError(f"settings line {number}: KEY=value 형식이어야 합니다.") # 실행 가능한 문장의 주입을 거부합니다.
        key, value = words[0].split("=", 1) # 첫 등호로 키와 값을 분리합니다.
        values[key] = value # 비밀정보 없는 문자열을 저장합니다.
    if values.get("ELASTIC_VERSION") != "9.5.3": # 패키지 설치 스크립트와 일치하는지 확인합니다.
        raise ValueError("ELASTIC_VERSION은 이 가이드에서 9.5.3입니다.") # 버전 불일치를 조기에 발견합니다.
    for key in ("ES_PRIVATE_IP", "KIBANA_PRIVATE_IP"): # 인증서 SAN과 접속 주소에 사용할 IP를 확인합니다.
        ipaddress.IPv4Address(values[key]) # 유효하지 않은 IP는 예외로 중단합니다.
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", values["AWS_REGION"]): # AWS 리전 이름을 제한합니다.
        raise ValueError("AWS_REGION 형식을 확인하세요.") # 오타를 보고합니다.
    for key in ("CLOUDTRAIL_QUEUE_URL", "CLOUDWATCH_QUEUE_URL", "WAF_QUEUE_URL", "GUARDDUTY_QUEUE_URL"): # 네 SQS 입력의 URL을 확인합니다.
        parsed = urlparse(values[key]) # URL을 분해합니다.
        if parsed.scheme != "https" or parsed.hostname != f'sqs.{values["AWS_REGION"]}.amazonaws.com' or "replace" in parsed.path: # 예시값과 잘못된 목적지를 거부합니다.
            raise ValueError(f"실제 Terraform 출력으로 {key}를 교체하세요.") # 필요한 변경 지점을 알려줍니다.
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", values["SNAPSHOT_BUCKET"]) or values["SNAPSHOT_BUCKET"].startswith("replace"): # 실제 버킷 이름인지 검사합니다.
        raise ValueError("SNAPSHOT_BUCKET을 실제 버킷으로 교체하세요.") # 예시 그대로의 실행을 막습니다.
    if not re.fullmatch(r"[a-zA-Z0-9/_-]+", values["SNAPSHOT_PREFIX"]): # 스냅샷 경로에서 쿼리 문자를 거부합니다.
        raise ValueError("SNAPSHOT_PREFIX 형식을 확인하세요.") # 잘못된 prefix를 알립니다.
    return values # 검증된 설정을 반환합니다.
