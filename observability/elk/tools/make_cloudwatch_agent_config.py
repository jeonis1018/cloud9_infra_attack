#!/usr/bin/env python3
"""신규 업무 서버의 파일 로그 설정만 만들며 AWS API나 Agent 실행은 하지 않는다.""" # 기존 Agent 설정은 자동으로 읽거나 변경하지 않는다.
import argparse # CLI에서 대상 리전·로그 그룹·명시적 앱 경로를 받는다.
import json # 주석을 지원하지 않는 Agent JSON을 올바르게 생성한다.
import os # 생성 파일의 기본 권한을 소유자 전용으로 제한한다.
from pathlib import Path, PurePosixPath # 관리자 OS와 무관하게 Linux 로그 경로를 검증한다.
import re # AWS 리전·로그 그룹 이름을 검증한다.

def build_config(region, log_group, app_logs): # 테스트 가능한 순수 함수로 Agent 설정을 조립한다.
    if region not in ("ap-northeast-2", "us-east-1"): # 제공 Terraform의 단일 리전 범위와 일치시킨다.
        raise ValueError("리전은 ap-northeast-2 또는 us-east-1을 선택하세요.") # 다른 리전은 가이드 확장 후 사용한다.
    if not re.fullmatch(r"[A-Za-z0-9._/#-]{1,512}", log_group) or log_group.startswith("aws/"): # CloudWatch Logs 이름 문법과 예약 접두사를 확인한다.
        raise ValueError("Terraform log_group_names.cloudwatch의 실제 이름을 넣으세요.") # 임의 ARN이나 빈 문자열을 받지 않는다.
    paths = [("/var/log/elk-validation.log", "validation")] # 첫 수집 검증은 별도 파일 한 개로 제한한다.
    seen = {paths[0][0]} # 중복 경로로 같은 파일을 두 번 수집하지 않게 한다.
    for index, raw_path in enumerate(app_logs, start=1): # 사용자가 명시적으로 추가한 앱 파일만 처리한다.
        if not PurePosixPath(raw_path).is_absolute() or any(char in raw_path for char in "\r\n\0*?[]") or ".." in PurePosixPath(raw_path).parts: # 상대 경로·glob·제어문자·상위 경로를 거부한다.
            raise ValueError("--app-log는 glob과 ..이 없는 실제 Linux 절대 파일 경로여야 합니다.") # 과도한 디렉터리 수집을 방지한다.
        if raw_path in seen: # 이미 등록한 파일인지 검사한다.
            raise ValueError(f"중복 파일 경로: {raw_path}") # 조용히 중복 이벤트를 만들지 않는다.
        seen.add(raw_path) # 다음 파일과 중복을 검사할 집합에 추가한다.
        paths.append((raw_path, f"app-{index}")) # 앱마다 구분되는 로그 스트림 suffix를 만든다.
    collect_list = [] # Agent가 읽을 파일 항목을 모은다.
    for file_path, suffix in paths: # 검증 파일과 선택한 앱 파일을 동일한 규칙으로 설정한다.
        collect_list.append({ # 한 파일의 CloudWatch Logs 전달 설정이다.
            "file_path": file_path, # 실제 업무 서버에서 존재·읽기 권한을 확인해야 한다.
            "log_group_name": log_group, # 새로 만들지 않고 Terraform이 출력한 그룹을 사용한다.
            "log_stream_name": "whs-elk-cloudwatch-{instance_id}-" + suffix, # 서비스·서버 ID·역할을 포함한 통일 이름으로 스트림을 구분한다.
            "encoding": "utf-8", # 첫 예제는 UTF-8 한 줄 로그를 가정한다.
        }) # 한 파일 설정을 끝낸다.
    return { # metrics·traces·로그 삭제 필터 없이 파일 로그만 수집한다.
        "agent": {"region": region, "run_as_user": "root"}, # 새 검증 서버의 파일 접근을 단순화하며 IAM 권한은 별도 최소화한다.
        "logs": { # 로그 전송 설정을 정의한다.
            "force_flush_interval": 5, # Agent 내부 전송 배치 대기 기준이며 전체 지연 SLA는 아니다.
            "logs_collected": {"files": {"collect_list": collect_list}}, # 명시한 파일 목록만 읽는다.
        }, # 로그 설정을 끝낸다.
    } # 설정 객체를 반환하며 retention 변경 권한은 요구하지 않는다.

def main(): # 파일 생성 CLI를 실행한다.
    parser = argparse.ArgumentParser(description=__doc__) # 실행 목적과 비변경 범위를 표시한다.
    parser.add_argument("--region", required=True) # 대상 리전을 필수로 받는다.
    parser.add_argument("--log-group", required=True) # Terraform output의 cloudwatch 그룹 이름을 받는다.
    parser.add_argument("--app-log", action="append", default=[]) # 선택한 앱 로그를 여러 번 지정할 수 있다.
    parser.add_argument("--output", required=True, type=Path) # 검토할 새 JSON 파일 경로를 받는다.
    args = parser.parse_args() # 명령행 옵션을 읽는다.
    config = build_config(args.region, args.log_group, args.app_log) # 값 검증과 JSON 내용 생성을 수행한다.
    os.umask(0o077) # 생성 파일과 새 부모 폴더를 다른 사용자에게 공개하지 않는다.
    args.output.parent.mkdir(parents=True, exist_ok=True) # 출력 폴더가 없으면 준비한다.
    with args.output.open("x", encoding="utf-8") as target: # 기존 설정 파일은 덮어쓰지 않고 오류로 중단한다.
        json.dump(config, target, ensure_ascii=False, indent=2) # Agent가 읽는 표준 JSON을 생성한다.
        target.write("\n") # 텍스트 파일 마지막 줄을 정상 종료한다.
    print(f"생성 완료: {args.output}; 적용 전에 대상 파일·기존 Agent owner·CWL 역할 권한을 확인하세요.") # 비밀정보 없이 생성 경로만 알린다.

if __name__ == "__main__": # import 시에는 파일을 쓰지 않는다.
    main() # 직접 실행한 경우에만 CLI를 처리한다.
