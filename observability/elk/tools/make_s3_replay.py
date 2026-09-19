#!/usr/bin/env python3
import argparse # 재처리할 원본 객체 한 개를 명시적으로 받습니다.
import datetime # 수동 알림을 만든 시각을 남깁니다.
import json # 주석 없는 SQS 메시지 본문을 생성합니다.
import pathlib # 지정한 출력 파일을 만듭니다.
import re # 버킷과 리전 이름의 오타를 확인합니다.
import urllib.parse # S3 이벤트가 사용하는 URL 인코딩을 적용합니다.
parser = argparse.ArgumentParser(description="원본 S3 객체 한 개의 재처리 알림을 생성합니다. AWS에 전송하지 않습니다.") # 생성과 전송을 분리합니다.
parser.add_argument("--bucket", required=True) # 이미 존재하는 원본 버킷입니다.
parser.add_argument("--key", required=True) # 다운로드할 정확한 기존 객체 키입니다.
parser.add_argument("--region", default="ap-northeast-2") # 원본과 소스 큐의 리전입니다.
parser.add_argument("--output", default="replay-message.json") # 검토할 알림 JSON 출력 경로입니다.
args = parser.parse_args() # 명령행 인자를 읽습니다.
if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", args.bucket) or not re.fullmatch(r"[a-z]{2}-[a-z]+-\d", args.region): # AWS 식별자 형식을 제한합니다.
    raise SystemExit("실제 버킷 이름과 리전 형식을 확인하세요.") # 형식이 잘못되면 중단합니다.
if not args.key or args.key.endswith("/"): # 폴더 marker의 재처리를 막습니다.
    raise SystemExit("폴더가 아닌 실제 로그 객체 한 개의 키가 필요합니다.") # 로그 파일을 지정하도록 합니다.
record = { # Filebeat가 읽을 S3 이벤트 알림의 필수 식별 정보를 만듭니다.
    "eventVersion": "2.1", # 표준 S3 알림 버전입니다.
    "eventSource": "aws:s3", # Filebeat의 S3 이벤트 해석을 사용합니다.
    "awsRegion": args.region, # 원본 버킷의 리전입니다.
    "eventTime": datetime.datetime.now(datetime.timezone.utc).isoformat(), # 원본 이벤트 발생 시각이 아니라 수동 알림 생성 시각입니다.
    "eventName": "ObjectCreated:Put", # 기존 객체를 다운로드하도록 지정하는 재처리 알림입니다.
    "s3": { # S3 객체의 실제 위치를 담습니다.
        "s3SchemaVersion": "1.0", # S3 하위 객체 스키마입니다.
        "configurationId": "manual-replay-reviewed", # 사람이 생성한 알림임을 구분합니다.
        "bucket": {"name": args.bucket, "arn": "arn:aws:s3:::" + args.bucket}, # 원본 버킷의 이름과 ARN입니다.
        "object": {"key": urllib.parse.quote_plus(args.key, safe="/")}, # 공백·특수 문자를 S3 이벤트 형식으로 인코딩합니다.
    }, # S3 객체 위치 정의를 마칩니다.
} # 알림 한 개의 정의를 마칩니다.
output = pathlib.Path(args.output) # 저장 경로를 확정합니다.
with output.open("x", encoding="utf-8") as stream: # 기존 검토 파일을 덮어쓰지 않습니다.
    json.dump({"Records": [record]}, stream, ensure_ascii=False, indent=2) # AWS가 받는 표준 JSON으로 저장합니다.
    stream.write("\n") # 파일 끝 줄바꿈을 추가합니다.
print(f"생성만 완료: {output}; AWS에는 전송하지 않았습니다.") # 작업 범위와 다음 검토 단계를 알립니다.
