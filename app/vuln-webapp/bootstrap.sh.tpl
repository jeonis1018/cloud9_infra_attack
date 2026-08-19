#!/bin/bash
set -e

# ==============================================
# 시스템 패키지 설치
# ==============================================
dnf update -y
dnf install -y python3 python3-pip

# ==============================================
# 앱 디렉토리 구성
# ==============================================
mkdir -p /opt/app/templates

cat > /opt/app/app.py << 'PYEOF'
${app_py}
PYEOF

cat > /opt/app/templates/index.html << 'HTMLEOF'
${index_html}
HTMLEOF

cat > /opt/app/templates/result.html << 'HTMLEOF'
${result_html}
HTMLEOF

# ==============================================
# Python 패키지 설치
# ==============================================
pip3 install flask requests

# ==============================================
# systemd 서비스로 등록 (재부팅해도 자동 실행되게)
# ==============================================
cat > /etc/systemd/system/vuln-webapp.service << 'SVCEOF'
[Unit]
Description=SSRF Vulnerable Web App (Cloud9 Project)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/app
ExecStart=/usr/bin/python3 /opt/app/app.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable vuln-webapp
systemctl start vuln-webapp
