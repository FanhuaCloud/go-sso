# Minimal OIDC SSO Server

这是一个最小可用的 Gin + Go OIDC Provider

## 项目结构

```text
main.go                  # 程序入口，只负责加载配置、初始化密钥、装配 HTTP 服务
internal/config/         # .env / 环境变量读取和配置校验
internal/oidc/           # RSA 密钥、JWT 签名、JWK、OIDC claims 和 token 工具
internal/server/         # Gin 路由、OIDC handlers、登录状态和模板渲染
internal/server/templates/ # 嵌入到二进制里的 HTML 模板
scripts/                 # 构建脚本
```

## 运行

```powershell
go run .
```

或运行已构建的二进制：

```powershell
.\go-sso.exe
```

默认监听：

```text
http://localhost:8080
```

打开首页可以看到服务运行状态：

```text
http://localhost:8080/
```

## 构建 Linux amd64

在 Windows PowerShell 中运行：

```powershell
.\scripts\build-linux-amd64.ps1
```

默认输出：

```text
dist/go-sso-linux-amd64/go-sso-linux-amd64
dist/go-sso-linux-amd64/.env.example
```

上传 `dist/go-sso-linux-amd64` 目录到 Linux 服务器后：

```bash
chmod +x ./go-sso-linux-amd64
cp .env.example .env
./go-sso-linux-amd64
```

## 修改页面

HTML 已拆到模板文件，并通过 Go `embed` 打包进二进制：

```text
internal/server/templates/home.html
internal/server/templates/login.html
```

修改模板后需要重新构建或重新运行 `go run .`，新的 HTML 才会进入二进制。

## OpenAI SSO 配置

默认值：

```text
Client ID: chatgpt
Client Secret: dev-secret-change-me
Discovery Endpoint: http://localhost:8080/.well-known/openid-configuration
```

回调地址来自 OpenAI SSO 配置页面，例如：

```text
https://external.auth.openai.com/sso/oidc/your-connection-id/callback
```

生产或公网测试时，`OIDC_ISSUER` 必须设置为外部可访问的 HTTPS 地址，否则 OpenAI 无法回调和读取 discovery/JWKS。

## 配置

复制示例配置到本地 `.env`：

```powershell
Copy-Item .env.example .env
```

`.env` 默认不提交到 Git。服务启动时会读取 `.env`，同时真实环境变量优先级更高，可以覆盖文件里的值。
复制后必须修改 `OIDC_CLIENT_SECRET` 和 `LOGIN_AUTH_CODE`，否则服务会拒绝启动。

```dotenv
ADDR=:8080
GIN_MODE=release
TRUSTED_PROXIES=
OIDC_ISSUER=https://your-public-domain.example
OIDC_CLIENT_ID=chatgpt
OIDC_CLIENT_SECRET=change-this-secret
OIDC_REDIRECT_URI=https://external.auth.openai.com/sso/oidc/your-connection-id/callback
CHATGPT_SSO_CONNECTION_ID=
CHATGPT_SSO_LOGIN_URL=
OIDC_ALLOW_ANY_CLIENT=0
OIDC_PRIVATE_KEY_FILE=private_key.pem
EMAIL_SUFFIX=@example.edu,@staff.example.edu
LOGIN_AUTH_CODE=change-this-login-code
TURNSTILE_ENABLED=0
TURNSTILE_SITEKEY=1x00000000000000000000AA
TURNSTILE_SECRET_KEY=1x0000000000000000000000000000000AA
HTTPS_ENABLED=0
HTTPS_CERT_FILE=
HTTPS_KEY_FILE=
```

如果不设置 `OIDC_PRIVATE_KEY_FILE`，服务每次启动会生成临时 RSA 签名密钥。正式使用建议固定私钥，否则重启后 JWKS 会变化。

`GIN_MODE=release` 会关闭 Gin 的 debug mode；本地调试时可以改成 `debug`。

`TRUSTED_PROXIES` 默认留空，表示不信任任何反向代理，避免 Gin 的 trust all proxies 警告。如果用本机 Nginx/Caddy 反代，可以配置：

```dotenv
TRUSTED_PROXIES=127.0.0.1,::1
```

`LOGIN_AUTH_CODE` 是登录页要求输入的固定授权码。生产环境必须改成强随机值，留空会拒绝登录。

`TURNSTILE_ENABLED=1` 会在登录页启用 Cloudflare Turnstile 人机验证。`TURNSTILE_SITEKEY` 用于前端页面，`TURNSTILE_SECRET_KEY` 只在后端校验时使用。示例配置使用 Cloudflare 官方测试 key，正式使用时请在 Cloudflare Dashboard 的 Turnstile 页面创建 widget 后替换为真实 key。

### 申请 Cloudflare Turnstile key

Cloudflare Turnstile 每个 widget 都会生成一组 key：`sitekey` 是公开标识，可以放到登录页；`secret key` 是后端校验凭据，只能放在服务端 `.env` 中。

申请步骤：

1. 登录 Cloudflare Dashboard：

```text
https://dash.cloudflare.com/
```

2. 进入左侧 Turnstile 页面，或者直接打开：

```text
https://dash.cloudflare.com/?to=/:account/turnstile
```

3. 点击 Add widget。

4. 填写 widget 信息：

```text
Widget name: go-sso-login
Hostname management: 填写你的 SSO 域名，例如 sso.example.com
Widget mode: 推荐选择 Managed
```

`Hostname management` 只需要填域名，不要带 `https://`、路径或端口。公网部署时填真实域名；本地调试可以继续使用 `.env.example` 里的测试 key。

5. 点击 Create 后，复制 Cloudflare 显示的 sitekey 和 secret key，写入 `.env`：

```dotenv
TURNSTILE_ENABLED=1
TURNSTILE_SITEKEY=你的-sitekey
TURNSTILE_SECRET_KEY=你的-secret-key
```

修改 `.env` 后需要重启服务。官方文档：

```text
https://developers.cloudflare.com/turnstile/get-started/widget-management/dashboard/
```

首页会在配置好 ChatGPT SSO 登录地址后显示“登录 ChatGPT”按钮。推荐配置：

```dotenv
CHATGPT_SSO_CONNECTION_ID=conn_0123abc
```

服务会生成官方 SSO Tile URL：

```text
https://chatgpt.com/auth/login?sso=true&connection=conn_0123abc
```

如果 `CHATGPT_SSO_CONNECTION_ID` 留空，服务会尝试从 `OIDC_REDIRECT_URI` 的 `/sso/oidc/{connection-id}/callback` 中自动推导。也可以用 `CHATGPT_SSO_LOGIN_URL` 直接覆盖完整跳转地址。

## HTTPS

OpenAI SSO 对接时，`OIDC_ISSUER` 必须是公网可访问的 HTTPS 地址。

### 方式一：程序直接启用 HTTPS

把证书文件和私钥文件放到服务器上，例如：

```text
/etc/ssl/go-sso/fullchain.pem
/etc/ssl/go-sso/privkey.pem
```

然后配置 `.env`：

```dotenv
ADDR=:443
OIDC_ISSUER=https://your-public-domain.example
HTTPS_ENABLED=1
HTTPS_CERT_FILE=/etc/ssl/go-sso/fullchain.pem
HTTPS_KEY_FILE=/etc/ssl/go-sso/privkey.pem
```

Linux 上监听 `:443` 通常需要 root 权限，或给二进制授权：

```bash
sudo setcap 'cap_net_bind_service=+ep' ./go-sso-linux-amd64
```

### 方式二：用 Nginx/Caddy 处理 HTTPS

如果用 Nginx、Caddy、Cloudflare Tunnel 等反向代理处理 HTTPS，程序本身保持 HTTP 即可：

```dotenv
ADDR=127.0.0.1:8080
OIDC_ISSUER=https://your-public-domain.example
HTTPS_ENABLED=0
TRUSTED_PROXIES=127.0.0.1,::1
```

反代需要传递这些头：

```nginx
proxy_set_header Host $host;
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

## 登录规则

用户访问 SSO 登录页后，需要输入邮箱和授权码。服务只接受 `EMAIL_SUFFIX` 配置的邮箱后缀，多个后缀用英文逗号分隔，默认是：

```text
*@example.edu
```

例如：

```dotenv
EMAIL_SUFFIX=@example.edu,@staff.example.edu
```

通过后会签发包含以下 claims 的 ID token：

```text
sub
email
email_verified
given_name
family_name
```
