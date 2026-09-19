#!/usr/bin/env python3
import argparse # 실행 인자를 처리합니다.
import os # 민감한 파일의 기본 권한을 제한합니다.
import pathlib # 인증서 경로를 다룹니다.
import shutil # 역할별 공개 CA 복사에 사용합니다.
import subprocess # OpenSSL을 shell 문자열 없이 실행합니다.
from common import load_settings # 검증된 설정 읽기 함수를 사용합니다.
parser = argparse.ArgumentParser(description="관리자 Linux에서만 CA와 역할별 인증서를 생성합니다.") # 용도를 명시합니다.
parser.add_argument("settings") # Terraform 값으로 채운 설정 파일을 받습니다.
parser.add_argument("output") # 기존에 존재하지 않는 비공개 출력 경로를 받습니다.
args = parser.parse_args() # 실행 인자를 읽습니다.
values = load_settings(args.settings) # 입력값을 검증합니다.
os.umask(0o077) # 새 private key는 소유자만 읽습니다.
root = pathlib.Path(args.output).resolve() # 인증서 작업 경로를 확정합니다.
root.mkdir(mode=0o700, parents=True, exist_ok=False) # 기존 CA를 실수로 덮어쓰지 않습니다.
ca_dir = root / "offline-ca" # CA private key를 별도 폴더로 분리합니다.
ca_dir.mkdir(mode=0o700) # CA 폴더 접근을 제한합니다.
subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-aes-256-cbc", "-pkeyopt", "rsa_keygen_bits:4096", "-out", str(ca_dir / "ca.key")], check=True) # OpenSSL이 직접 비밀번호를 입력받아 CA private key를 암호화합니다.
subprocess.run(["openssl", "req", "-x509", "-new", "-sha256", "-days", "3650", "-key", str(ca_dir / "ca.key"), "-out", str(ca_dir / "ca.crt"), "-subj", "/CN=whs-elk-pki-root-ca", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True) # 비밀번호는 OpenSSL 프롬프트로만 입력하며 공통 이름의 CA 인증서를 만듭니다.
for role, address in (("elasticsearch", values["ES_PRIVATE_IP"]), ("kibana", values["KIBANA_PRIVATE_IP"])): # 서버 역할마다 별개의 키를 만듭니다.
    folder = root / role # 역할별로 전송 가능한 폴더를 분리합니다.
    folder.mkdir(mode=0o700) # 역할 폴더의 읽기 권한을 제한합니다.
    extensions = folder / "extensions.cnf" # 인증서의 SAN과 용도를 명시할 파일입니다.
    extensions.write_text(f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=IP:{address},IP:127.0.0.1,DNS:localhost\n", encoding="utf-8") # 인증서 SAN에 실제 private IP와 SSM 접속 localhost를 포함합니다.
    subprocess.run(["openssl", "req", "-new", "-newkey", "rsa:3072", "-nodes", "-keyout", str(folder / f"{role}.key"), "-out", str(folder / f"{role}.csr"), "-subj", f"/CN=whs-elk-{role}-tls"], check=True) # 공통 이름 규칙으로 서버별 키와 서명 요청을 생성합니다.
    subprocess.run(["openssl", "x509", "-req", "-sha256", "-days", "365", "-in", str(folder / f"{role}.csr"), "-CA", str(ca_dir / "ca.crt"), "-CAkey", str(ca_dir / "ca.key"), "-CAcreateserial", "-extfile", str(extensions), "-out", str(folder / f"{role}.crt")], check=True) # CA 비밀번호를 인터랙티브하게 입력하여 서버 인증서를 서명합니다.
    shutil.copyfile(ca_dir / "ca.crt", folder / "ca.crt") # 서버에 필요한 공개 CA 인증서만 복사합니다.
    (folder / f"{role}.csr").unlink() # 완료된 서명 요청은 전송 대상에서 제거합니다.
    extensions.unlink() # 발급용 임시 설정은 전송 대상에서 제거합니다.
collector = root / "collector" # collector는 TLS 서버 역할이 없어 CA만 필요합니다.
collector.mkdir(mode=0o700) # collector 배포 폴더를 만듭니다.
shutil.copyfile(ca_dir / "ca.crt", collector / "ca.crt") # Elasticsearch를 검증할 공개 CA를 복사합니다.
print(f"역할별 전송 폴더: {root}/collector, {root}/elasticsearch, {root}/kibana") # 비밀 내용 대신 전송할 경로만 알려줍니다.
print(f"절대 전송하지 않을 CA private key: {ca_dir}/ca.key") # CA 서명 권한을 EC2에 배포하지 않도록 명시합니다.
