#!/usr/bin/env python3
import base64
import os

import boto3
import requests
from botocore.client import Config
from botocore.exceptions import ClientError
from flask import Flask, redirect, render_template, request, url_for

app = Flask(__name__)

PROFILE_BUCKET_NAME = os.environ.get("PROFILE_BUCKET_NAME", "")
AWS_REGION = os.environ.get("AWS_REGION", "ap-northeast-2")
NICKNAME = "Kim"
PROFILE_KEY = "profile/current"

# ap-northeast-2(서울) 리전은 SigV4만 지원. endpoint_url을 리전 엔드포인트로 고정해서
# 서명에 쓰인 host와 실제 요청 host가 어긋나 SignatureDoesNotMatch가 나는 걸 방지
s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
    endpoint_url=f"https://s3.{AWS_REGION}.amazonaws.com",
    config=Config(signature_version="s3v4"),
)


def get_profile_image_url():
    try:
        s3.head_object(Bucket=PROFILE_BUCKET_NAME, Key=PROFILE_KEY)
    except ClientError:
        return None
    return s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": PROFILE_BUCKET_NAME, "Key": PROFILE_KEY},
        ExpiresIn=3600,
    )


@app.route("/")
def index():
    return render_template("index.html", nickname=NICKNAME, photo_url=get_profile_image_url())


@app.route("/preview", methods=["GET"])
def preview():
    url = request.args.get("url", "")
    if not url:
        return render_template("index.html", nickname=NICKNAME, photo_url=get_profile_image_url(), error="URL을 입력하세요"), 400

    try:
        res = requests.get(url, timeout=5)
    except requests.exceptions.RequestException as e:
        return render_template(
            "index.html", nickname=NICKNAME, photo_url=get_profile_image_url(), preview_url=url, error=str(e)
        ), 502

    content_type = res.headers.get("Content-Type", "")
    if content_type.startswith("image/"):
        preview_image = base64.b64encode(res.content).decode("utf-8")
        return render_template(
            "index.html",
            nickname=NICKNAME,
            photo_url=get_profile_image_url(),
            preview_url=url,
            preview_image=preview_image,
            preview_content_type=content_type,
        )

    # 이미지가 아닌 응답은 원문 그대로 에러창에 노출한다 (SSRF 오라클)
    return render_template(
        "index.html", nickname=NICKNAME, photo_url=get_profile_image_url(), preview_url=url, error=res.text
    )


@app.route("/change", methods=["POST"])
def change():
    url = request.form.get("url", "")
    if not url:
        return render_template("index.html", nickname=NICKNAME, photo_url=get_profile_image_url(), error="URL을 입력하세요"), 400

    try:
        res = requests.get(url, timeout=5)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        return render_template(
            "index.html", nickname=NICKNAME, photo_url=get_profile_image_url(), preview_url=url, error=str(e)
        ), 502

    content_type = res.headers.get("Content-Type", "")
    if not content_type.startswith("image/"):
        return render_template(
            "index.html",
            nickname=NICKNAME,
            photo_url=get_profile_image_url(),
            preview_url=url,
            error="이미지 파일만 프로필로 설정할 수 있습니다",
        ), 400

    s3.put_object(
        Bucket=PROFILE_BUCKET_NAME,
        Key=PROFILE_KEY,
        Body=res.content,
        ContentType=content_type,
        Tagging="image=true",
    )
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
