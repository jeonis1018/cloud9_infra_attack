#!/usr/bin/env python3
from flask import Flask, request, render_template
import requests

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/fetch", methods=["GET"])
def fetch():
    url = request.args.get("url", "")
    if not url:
        return render_template("result.html", url=url, body="", error="Invalid URL"), 400
    try:
        res = requests.get(url)
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        return render_template("result.html", url=url, body="", error=e), 502
    body = res.text
    return render_template("result.html", url=url, body=body)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
