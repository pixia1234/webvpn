import os
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


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
    # keep redirects visible so we can rewrite Location header
    return requests.get(url, headers=headers, timeout=10, allow_redirects=False)


def rewrite_html(base_url: str, html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("href", "src", "action"):
            val = tag.get(attr)
            if not val:
                continue
            joined = urljoin(base_url, val)
            tag[attr] = url_for("proxy", url=joined)
    return str(soup)


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


@app.route("/proxy", methods=["GET", "POST"])
def proxy():
    auth_redirect = enforce_authentication()
    if auth_redirect:
        return auth_redirect

    target_url = (request.args.get("url") or request.form.get("url") or "").strip()
    if not target_url:
        return render_template("index.html", error="Please provide a URL")

    if not host_allowed(target_url):
        abort(400, description="URL not allowed")

    try:
        upstream = proxy_fetch(target_url)
    except requests.RequestException as exc:
        return render_template("index.html", error=f"Request failed: {exc}")

    # Handle redirect by rewriting Location to go through proxy
    if 300 <= upstream.status_code < 400 and "Location" in upstream.headers:
        location = urljoin(target_url, upstream.headers["Location"])
        proxied = url_for("proxy", url=location, _external=False)
        resp = redirect(proxied, code=upstream.status_code)
        return resp

    content_type = upstream.headers.get("Content-Type", "")
    is_html = content_type.startswith("text/html")

    body = upstream.content
    if is_html:
        rewritten = rewrite_html(target_url, upstream.text)
        body = rewritten.encode(upstream.encoding or "utf-8", errors="replace")

    resp = Response(body, status=upstream.status_code)
    for key, value in upstream.headers.items():
        if key.lower() in {"content-length", "transfer-encoding", "connection"}:
            continue
        if key.lower() == "content-encoding" and is_html:
            continue
        resp.headers[key] = value
    resp.headers["Content-Type"] = content_type or "application/octet-stream"
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
