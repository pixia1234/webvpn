# WebVPN Gateway

轻量级基于 Flask 的“资源访问网关”示例，可通过浏览器登录后转发外部 HTTP/HTTPS 请求，类似网页 VPN。

## 功能
- 登录认证（默认账号/密码 `admin`/`admin`，可用环境变量覆盖）
- 输入 URL 后由服务端代理请求，返回内容，自动重写 HTML 内链接指向网关（便于继续跳转）
- 可选主机允许列表（限制可访问的目标域名）

## 本地运行
```bash
pip install -r requirements.txt

export WEBVPN_USER=admin
export WEBVPN_PASSWORD=admin
# 允许的目标主机，逗号分隔；留空表示不限制
export WEBVPN_ALLOWED_HOSTS="example.com,api.example.com"
export WEBVPN_SECRET="change-me"

python app.py
```
启动后访问 `http://localhost:8000`，登录后输入目标 URL。

## 配置项（环境变量）
- `WEBVPN_USER` / `WEBVPN_PASSWORD`：登录凭证
- `WEBVPN_SECRET`：Flask Session 密钥
- `WEBVPN_ALLOWED_HOSTS`：允许访问的主机白名单，逗号分隔；留空表示不限制
- `PORT`：监听端口，默认 8000

## 注意事项
- 示例用途；生产需放在反向代理后并强制 HTTPS。
- 未对大文件/二进制流做透传优化，展示时省略二进制内容。
- 如启用主机白名单，请填写完整域名（如 `example.com`）。***
