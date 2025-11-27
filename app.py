import os
from urllib.parse import urlparse

import requests
from flask import Flask, abort, redirect, render_template, request, session, url_for


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("WEBVPN_SECRET", "dev-secret-change-me")

# Comma-separated allowlist of hosts. Leave empty to allow any host (not recommended for production).
allowed_hosts = [host.strip() for host in os.getenv("WEBVPN_ALLOWED_HOSTS", "").split(",") if host.strip()]

username = os.getenv("WEBVPN_USER", "admin")
password = os.getenv("WEBVPN_PASSWORD", "admin")

def is_authenticated() -> bool:
    return session.get("user") == username


def enforce_authentication():
    if not is_authenticated():
        return redirect(url_for("login"))
    return None


def host_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if not allowed_hosts:
        return True
    return parsed.hostname in allowed_hosts


def proxy_fetch(url: str):
    headers = {}
    for header in ["User-Agent", "Accept", "Accept-Language"]:
        if header in request.headers:
            headers[header] = request.headers[header]
    return requests.get(url, headers=headers, timeout=10, allow_redirects=True)


@app.route("/")
def index():
    auth_redirect = enforce_authentication()
    if auth_redirect:
        return auth_redirect
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("username") == username and request.form.get("password") == password:
            session["user"] = username
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/fetch", methods=["POST"])
def fetch():
    auth_redirect = enforce_authentication()
    if auth_redirect:
        return auth_redirect

    target_url = request.form.get("url", "").strip()
    if not target_url:
        return render_template("index.html", error="Please provide a URL")

    if not host_allowed(target_url):
        abort(400, description="URL not allowed")

    try:
        upstream = proxy_fetch(target_url)
    except requests.RequestException as exc:
        return render_template("index.html", error=f"Request failed: {exc}")

    content_type = upstream.headers.get("Content-Type", "")
    is_text = content_type.startswith("text/") or "json" in content_type

    return render_template(
        "result.html",
        url=target_url,
        status=upstream.status_code,
        headers=upstream.headers,
        content=upstream.text if is_text else "<binary content omitted>",
        is_text=is_text,
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
