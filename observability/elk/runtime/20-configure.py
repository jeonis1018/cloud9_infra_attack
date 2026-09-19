#!/usr/bin/env python3
import argparse # 역할과 입력 경로를 읽습니다.
import os # root 권한을 확인합니다.
import pathlib # 설정 파일 경로를 다룹니다.
import shutil # 인증서와 정규화 코드를 복사합니다.
import subprocess # 시스템 명령을 인자 배열로 실행합니다.
from common import load_settings # 비밀정보 없는 설정을 검증합니다.
parser = argparse.ArgumentParser(description="새 EC2에만 최초 설정을 배치합니다. 기존 서비스 설정은 검토 후 변경하세요.") # 첫 구축 용도를 명확히 합니다.
parser.add_argument("role", choices=["collector", "elasticsearch", "kibana"]) # 허용한 세 역할만 받습니다.
parser.add_argument("settings") # 실제 리소스 값을 담은 설정 파일입니다.
parser.add_argument("certs") # 이 역할의 인증서만 내려받은 폴더입니다.
args = parser.parse_args() # 인자를 읽습니다.
if os.geteuid() != 0: # 시스템 설정 쓰기 권한을 확인합니다.
    raise SystemExit("sudo python3로 실행하세요.") # 비권한 실행을 막습니다.
values = load_settings(args.settings) # IP, 리전, SQS, 버킷을 검증합니다.
base = pathlib.Path(__file__).resolve().parent # 실행 파일을 기준으로 템플릿을 찾습니다.
certs = pathlib.Path(args.certs).resolve() # 받아온 역할별 인증서 폴더입니다.
role = args.role # 선택한 역할을 저장합니다.
marker = pathlib.Path(f"/etc/elk-guide-{role}.configured") # 최초 구성 완료 여부를 추적합니다.
if marker.exists(): # 기존 배포에 실수로 기본 설정을 다시 덮어쓰지 않습니다.
    raise SystemExit(f"이미 구성됨: {marker}; 설정 파일을 직접 검토하여 수정하세요.") # 반복 실행 대신 명시적 변경을 요구합니다.
def install_text(template, destination, group): # 주석을 유지하며 안전하게 설정을 생성합니다.
    text = (base / "templates" / template).read_text(encoding="utf-8") # 저장소의 템플릿을 읽습니다.
    for key, value in values.items(): # 검증한 비밀정보 없는 값만 치환합니다.
        text = text.replace(f"__{key}__", value) # Logstash의 ${ES_API_KEY}는 치환하지 않습니다.
    path = pathlib.Path(destination) # 목적지 경로를 확정합니다.
    path.parent.mkdir(parents=True, exist_ok=True) # 필요한 설정 폴더를 만듭니다.
    path.write_text(text, encoding="utf-8") # 주석이 있는 설정을 기록합니다.
    path.chmod(0o640) # 소유자와 서비스 그룹만 읽을 수 있습니다.
    shutil.chown(path, user="root", group=group) # 서비스 사용자에게 읽기만 허용합니다.
def install_certs(service): # 이 서버에 필요한 인증서만 배치합니다.
    folder = pathlib.Path(f"/etc/{service}/certs") # 서비스 설정 경로 아래 TLS 폴더입니다.
    folder.mkdir(mode=0o750, parents=True, exist_ok=True) # 디렉터리 접근을 제한합니다.
    shutil.chown(folder, user="root", group=service) # 해당 서비스만 접근하게 합니다.
    names = ["ca.crt"] if role == "collector" else ["ca.crt", f"{role}.crt", f"{role}.key"] # collector에는 CA만 복사합니다.
    for name in names: # 역할별 파일을 하나씩 설치합니다.
        target = folder / name # 서버에 둘 파일 경로입니다.
        shutil.copyfile(certs / name, target) # 수신 폴더의 정확한 파일만 복사합니다.
        target.chmod(0o640) # private key 포함 파일을 다른 사용자에게 노출하지 않습니다.
        shutil.chown(target, user="root", group=service) # 서비스 계정에게만 읽기 권한을 줍니다.
if role == "elasticsearch": # 저장 서버의 설정을 만듭니다.
    install_certs("elasticsearch") # 서버 인증서와 CA를 배치합니다.
    install_text("elasticsearch.yml.in", "/etc/elasticsearch/elasticsearch.yml", "elasticsearch") # TLS와 단일 노드 구성을 설치합니다.
    pathlib.Path("/etc/sysctl.d/90-elasticsearch.conf").write_text("vm.max_map_count=1048576 # Lucene 메모리 매핑 공간을 확보합니다.\n", encoding="utf-8") # 커널 설정을 영구 저장합니다.
    subprocess.run(["sysctl", "--system"], check=True) # 현재 커널에도 메모리 매핑 설정을 반영합니다.
    keystore = "/usr/share/elasticsearch/bin/elasticsearch-keystore" # 패키지의 keystore 도구입니다.
    existing = subprocess.run([keystore, "list"], check=True, capture_output=True, text=True).stdout.splitlines() # 패키지 자동 생성 설정이 있는지 확인합니다.
    for key in ("xpack.security.http.ssl.keystore.secure_password", "xpack.security.transport.ssl.keystore.secure_password", "xpack.security.transport.ssl.truststore.secure_password"): # 새 PEM 구성과 충돌할 자동 설정만 대상으로 합니다.
        if key in existing: # 실제로 존재하는 설정만 지웁니다.
            subprocess.run([keystore, "remove", key], check=True) # PKCS12의 과거 비밀번호 설정을 제거합니다.
elif role == "collector": # 수집 서버의 설정을 만듭니다.
    install_certs("logstash") # Elasticsearch 검증용 CA만 설치합니다.
    install_text("filebeat.yml.in", "/etc/filebeat/filebeat.yml", "root") # SQS 네 개를 읽는 Filebeat 설정입니다.
    install_text("logstash.yml.in", "/etc/logstash/logstash.yml", "logstash") # persistent queue 설정을 설치합니다.
    install_text("pipelines.yml.in", "/etc/logstash/pipelines.yml", "logstash") # 처리할 파이프라인을 지정합니다.
    install_text("aws-security.conf.in", "/etc/logstash/conf.d/aws-security.conf", "logstash") # Beats 입력과 ES 출력을 설정합니다.
    shutil.copyfile(base / "normalize.rb", "/etc/logstash/normalize.rb") # 서비스별 파싱 코드를 설치합니다.
    pathlib.Path("/etc/logstash/normalize.rb").chmod(0o640) # 코드 읽기 권한을 제한합니다.
    shutil.chown("/etc/logstash/normalize.rb", user="root", group="logstash") # Logstash가 코드를 읽게 합니다.
else: # Kibana 서버를 구성합니다.
    install_certs("kibana") # HTTPS 서버 인증서와 ES 검증용 CA를 배치합니다.
    install_text("kibana.yml.in", "/etc/kibana/kibana.yml", "kibana") # 브라우저와 ES 양쪽 TLS를 설정합니다.
marker.write_text("초기 설정 완료. 인증 키 구성과 서비스 시작은 별도입니다.\n", encoding="utf-8") # 설치 상태를 기록합니다.
marker.chmod(0o600) # 상태 파일을 root만 읽게 합니다.
print("설정 완료. 30-admin.py 및 문서의 역할별 시작 절차를 진행하세요.") # 자동 시작 전에 인증 단계가 남았음을 알립니다.
