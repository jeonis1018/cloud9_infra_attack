#!/usr/bin/env python3
import ast # Python 코드를 실행하지 않고 문법을 검사합니다.
import gzip # 샘플 gzip의 압축 무결성을 확인합니다.
import io # Python 토큰 검사에 메모리 스트림을 사용합니다.
import json # 표준 JSON 샘플을 읽습니다.
import os # 캐시와 실행 상태 디렉터리를 제외하며 파일을 탐색합니다.
import pathlib # 실행 위치와 무관하게 패키지 루트를 찾습니다.
import re # 문서 링크와 코드 블록을 검사합니다.
import sys # 오류가 있으면 실패 종료 코드를 반환합니다.
import tokenize # 문자열 속 #과 실제 Python 주석을 구분합니다.
root = pathlib.Path(__file__).resolve().parents[1] # tools의 상위가 패키지 루트입니다.
errors = [] # 실패 항목을 모아 한 번에 보고합니다.
files = [] # 실제 배포 대상 코드와 문서를 모읍니다.
for folder, directories, names in os.walk(root): # 패키지 아래를 순회합니다.
    directories[:] = [name for name in directories if name not in {".terraform", "__pycache__", ".git", ".private", "private-pki"}] # 도구 캐시와 비공개 상태를 제외합니다.
    files.extend(pathlib.Path(folder) / name for name in names if not name.endswith((".pyc", ".tfstate", ".tfplan"))) # 생성 상태 파일은 검사 자료로 읽지 않습니다.
for path in files: # 각 문서와 코드를 확인합니다.
    relative = path.relative_to(root).as_posix() # 실패 위치를 읽기 쉽게 만듭니다.
    is_code = path.suffix in {".py", ".rb", ".tf", ".hcl", ".sh", ".in", ".example"} # 줄별 주석 대상 파일입니다.
    if not is_code and path.suffix != ".md": # 바이너리와 표준 JSON에는 주석 규칙을 적용하지 않습니다.
        continue # 별도 샘플 검사로 넘어갑니다.
    body = path.read_text(encoding="utf-8-sig") # UTF-8 한국어 파일을 읽습니다.
    lines = body.splitlines() # 문서의 실제 줄 번호를 유지합니다.
    if path.suffix == ".py": # Python 문법과 실제 주석 토큰을 확인합니다.
        try: # 실패 위치를 수집합니다.
            ast.parse(body, filename=relative) # 코드를 실행하지 않는 구문 분석입니다.
            comment_lines = {token.start[0] for token in tokenize.generate_tokens(io.StringIO(body).readline) if token.type == tokenize.COMMENT} # 실제 주석이 있는 줄 번호입니다.
            errors.extend(f"{relative}:{number}: Python 줄 주석 없음" for number, line in enumerate(lines, 1) if line.strip() and number not in comment_lines) # 모든 유효 줄의 설명을 확인합니다.
        except (SyntaxError, tokenize.TokenError) as error: # 파싱 실패도 보고합니다.
            errors.append(f"{relative}: {error}") # 문법 오류를 기록합니다.
    elif is_code: # HCL·YAML·Ruby·Bash의 설명 누락을 정적으로 검사합니다.
        errors.extend(f"{relative}:{number}: 줄 주석 없음" for number, line in enumerate(lines, 1) if line.strip() and "#" not in line) # 최종 문법 검사는 해당 언어 도구가 담당합니다.
    if path.suffix == ".md": # 문서의 코드와 상대 링크를 검사합니다.
        language = None # 현재 열린 코드 블록이 없는 상태입니다.
        for number, line in enumerate(lines, 1): # 코드 블록의 경계를 읽습니다.
            if line.startswith("```"): # 이 패키지에서 사용하는 fence 구분자입니다.
                language = line[3:].strip() if language is None else None # 블록을 열거나 닫습니다.
            elif language in {"bash", "sh", "powershell", "hcl", "terraform", "yaml", "python", "ruby"} and line.strip() and "#" not in line: # 실행 예제에도 줄 설명이 필요합니다.
                errors.append(f"{relative}:{number}: 코드 예제의 줄 주석 없음") # 설명 누락을 기록합니다.
        if language is not None: # 닫히지 않은 fence가 있는지 확인합니다.
            errors.append(f"{relative}: 닫히지 않은 코드 블록") # 렌더링 문제를 알립니다.
        for target in re.findall(r"\]\(([^)]+)\)", body): # Markdown 링크의 대상을 읽습니다.
            if target.startswith(("https://", "http://", "#", "mailto:")): # 외부 URL의 실시간 연결 검사는 수행하지 않습니다.
                continue # 로컬 링크만 확인합니다.
            destination = target.split("#", 1)[0].strip("<>") # 문서 내부 앵커와 경로 감싸기를 분리합니다.
            if destination and not (path.parent / destination).exists(): # 참조 파일의 존재를 확인합니다.
                errors.append(f"{relative}: 없는 로컬 링크 {destination}") # 깨진 참조를 기록합니다.
for sample in (root / "samples").glob("*.json.gz"): # 정상 형식 gzip 샘플을 읽습니다.
    try: # gzip과 JSON 오류를 함께 확인합니다.
        decoded = gzip.decompress(sample.read_bytes()) # CRC를 포함해 압축을 검사합니다.
        json.loads(decoded) # 주석 없는 표준 JSON을 확인합니다.
        if decoded != sample.with_suffix("").read_bytes(): # 사람이 읽는 JSON과 실제 압축본을 비교합니다.
            errors.append(f"{sample.name}: JSON 원문과 압축본 불일치") # 오래된 샘플을 탐지합니다.
    except (OSError, ValueError, EOFError) as error: # 깨진 gzip/JSON을 보고합니다.
        errors.append(f"{sample.name}: {error}") # 오류를 모읍니다.
if errors: # 하나라도 실패하면 성공으로 표시하지 않습니다.
    print("\n".join(errors)) # 코드·문서 오류의 위치만 출력합니다.
    sys.exit(1) # 자동 검사에서 실패를 인식하게 합니다.
print(f"PASS: 코드·문서 {len(files)}개 파일의 정적 검사, 상대 링크, 줄 주석, 샘플 gzip/JSON 일치") # 검사 범위를 명시합니다.
print("AWS 호출·EC2 설치·실제 Filebeat/Logstash 통합 검증은 수행하지 않았습니다.") # 정적 검사와 배포 검증을 구분합니다.
