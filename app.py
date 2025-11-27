import os
from base64 import urlsafe_b64decode, urlsafe_b64encode
from urllib.parse import urljoin, urlparse
import re

import requests
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
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
# AES key for URL tokens (AES-128). Provide 16+ chars via WEBVPN_AES_KEY.
aes_key_raw = os.getenv("WEBVPN_AES_KEY", "dev-aes-key").encode("utf-8")
aes_key = aes_key_raw[:16].ljust(16, b"0")

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
    headers.setdefault("Accept-Encoding", "identity")
    # keep redirects visible so we can rewrite Location header
    return requests.get(url, headers=headers, timeout=10, allow_redirects=False)


def pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        return data
    return data[:-pad_len]


def encrypt_url(url: str) -> str:
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    enc = cipher.encrypt(pad(url.encode("utf-8")))
    token = urlsafe_b64encode(iv + enc).decode("ascii")
    return token


def decrypt_token(token: str) -> str:
    raw = urlsafe_b64decode(token.encode("ascii"))
    iv, enc = raw[:16], raw[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    dec = unpad(cipher.decrypt(enc))
    return dec.decode("utf-8", errors="ignore")


def rewrite_html(base_url: str, html: str, token: str) -> str:
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    display_url = parsed.netloc + parsed.path
    if parsed.params:
        display_url += f";{parsed.params}"
    if parsed.query:
        display_url += f"?{parsed.query}"

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("href", "src", "action"):
            val = tag.get(attr)
            if not val:
                continue
            joined = urljoin(base_url, val)
            tag[attr] = url_for("proxy", token=encrypt_url(joined))
    bar = soup.new_tag("div", id="webvpn-bar")
    form = soup.new_tag("form", attrs={"action": url_for("proxy"), "method": "get", "id": "webvpn-form"})
    select = soup.new_tag("select", attrs={"name": "scheme"})
    for opt in ("https", "http"):
        option = soup.new_tag("option", value=opt)
        if scheme == opt:
            option.attrs["selected"] = "selected"
        option.string = f"{opt}://"
        select.append(option)
    form.append(select)
    input_url = soup.new_tag(
        "input",
        attrs={"type": "text", "name": "url", "value": display_url, "placeholder": "target URL"},
    )
    submit = soup.new_tag("button", type="submit")
    submit.string = "Go"
    form.append(input_url)
    form.append(submit)
    bar.append(form)
    body = soup.body or soup
    body.insert(0, bar)
    style = soup.new_tag("style")
    style.string = """
#webvpn-bar{
  padding:10px 14px;
  background:linear-gradient(135deg,rgba(16,24,40,0.95),rgba(16,24,40,0.9));
  color:#e7edf5;
  font-family:'Space Grotesk','IBM Plex Sans','Segoe UI',sans-serif;
  font-size:14px;
  border-bottom:1px solid rgba(91,192,190,0.2);
  box-shadow:0 12px 25px rgba(0,0,0,0.25);
  position:sticky;
  top:0;
  z-index:9999;
  box-sizing:border-box;
}
#webvpn-form{
  display:flex;
  align-items:center;
  gap:10px;
}
#webvpn-form select,
#webvpn-form input,
#webvpn-form button{
  height:40px;
  padding:0 12px;
  border-radius:10px;
  border:1px solid rgba(255,255,255,0.14);
  background:rgba(255,255,255,0.05);
  color:#e7edf5;
  transition:border 0.2s ease, box-shadow 0.2s ease;
  -webkit-appearance:none;
  appearance:none;
}
#webvpn-form input{
  flex:1;
  min-width:260px;
}
#webvpn-form select:focus,
#webvpn-form input:focus{
  border-color:#5bc0be;
  box-shadow:0 0 0 2px rgba(91,192,190,0.25);
}
#webvpn-form button{
  background:linear-gradient(135deg,#5bc0be,#4cb4b2);
  color:#0b132b;
  border:none;
  font-weight:700;
  cursor:pointer;
  box-shadow:0 10px 24px rgba(75,180,178,0.25);
}
#webvpn-form button:hover{transform:translateY(-1px);}
"""
    (soup.head or soup).append(style)
    return str(soup)


def rewrite_css(base_url: str, css_text: str) -> str:
    """
    Rewrite url(...) references in CSS to go through proxy tokens.
    """
    pattern = re.compile(r"url\\(\\s*([\"']?)(?!data:)([^)\"']+)\\1\\s*\\)", re.IGNORECASE)

    def repl(match):
        quote = match.group(1)
        target = match.group(2)
        joined = urljoin(base_url, target)
        proxied = url_for("proxy", token=encrypt_url(joined))
        return f"url({quote}{proxied}{quote})"

    return pattern.sub(repl, css_text)


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

    token = request.args.get("token", "").strip()
    target_url = ""
    scheme = (request.args.get("scheme") or request.form.get("scheme") or "https").strip().lower()
    if scheme not in {"http", "https"}:
        scheme = "https"
    if token:
        try:
            target_url = decrypt_token(token)
        except Exception:
            abort(400, description="Invalid token")
    else:
        target_url = (request.args.get("url") or request.form.get("url") or "").strip()
        if not target_url and request.args and session.get("last_target"):
            # Fallback for forms/links that lost token: reuse last target and append current query
            base = session["last_target"]
            qs = request.query_string.decode("utf-8")
            target_url = base.split("?", 1)[0]
            if qs:
                target_url = f"{target_url}?{qs}"
        if target_url and "://" not in target_url:
            target_url = f"{scheme}://{target_url}"

    if not target_url:
        return render_template("index.html", error="Please provide a URL")

    if not token:
        # Redirect to tokenized URL to avoid exposing raw target in the address bar
        fresh_token = encrypt_url(target_url)
        return redirect(url_for("proxy", token=fresh_token), code=302)

    if not host_allowed(target_url):
        abort(400, description="URL not allowed")

    try:
        upstream = proxy_fetch(target_url)
    except requests.RequestException as exc:
        return render_template("index.html", error=f"Request failed: {exc}")

    session["last_target"] = target_url

    # Handle redirect by rewriting Location to go through proxy
    if 300 <= upstream.status_code < 400 and "Location" in upstream.headers:
        location = urljoin(target_url, upstream.headers["Location"])
        proxied = url_for("proxy", token=encrypt_url(location), _external=False)
        resp = redirect(proxied, code=upstream.status_code)
        resp.headers["X-Proxy-Target"] = target_url
        return resp

    content_type = upstream.headers.get("Content-Type", "")
    ct_lower = content_type.lower()
    is_html = "html" in ct_lower
    is_css = "css" in ct_lower

    body = upstream.content
    if is_html:
        current_token = encrypt_url(target_url)
        rewritten = rewrite_html(target_url, upstream.text, current_token)
        body = rewritten.encode(upstream.encoding or "utf-8", errors="replace")
    elif is_css:
        current_token = encrypt_url(target_url)
        rewritten = rewrite_css(target_url, upstream.text)
        body = rewritten.encode(upstream.encoding or "utf-8", errors="replace")

    resp = Response(body, status=upstream.status_code)
    for key, value in upstream.headers.items():
        k = key.lower()
        if k in {"content-length", "transfer-encoding", "connection", "content-encoding"}:
            continue
        resp.headers[key] = value
    resp.headers["Content-Type"] = content_type or "application/octet-stream"
    resp.headers["X-Proxy-Target"] = target_url
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
