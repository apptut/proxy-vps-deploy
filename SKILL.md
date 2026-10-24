---
name: proxy-vps-deploy
description: 通过 SSH 为 Debian 12 x86_64 VPS 部署 Reality、Hysteria2、AnyTLS，生成 Clash 配置、收紧 IPv4/IPv6 防火墙并验证连接。用于新建个人代理 VPS、复用该部署方案或检查其端口；不用于业务 HTTP 反向代理。
---

# Proxy VPS 部署

只需用户提供主机地址、SSH 端口（默认 22）、用户名（本配方需 root）及密码或已有 SSH 私钥。目标是新 VPS；发现已有代理、业务监听或现有防火墙时先审计并按实际用途整合，脚本会拒绝直接覆盖。

## 执行

技能内路径相对于本文件。脚本仅需 Python 3.9+ 标准库、OpenSSH、curl；本地验证需要 Mihomo，自动识别 macOS Clash Verge 内核，也支持 `--core /path/to/mihomo`。

1. 用 `python3 scripts/deploy.py audit --host HOST --port PORT --user root` 检查目标。密码默认由隐藏终端输入；已有密钥使用 `--identity PATH`。Agent 已收到密码时，可通过受控子进程 stdin 配合 `--password-stdin`，不要将密码放在命令参数、终端回显、输出或持久文件里；不要让用户反复提供已给过的账号。
2. 确认是兼容的新机后执行 `python3 scripts/deploy.py deploy --host HOST --port PORT --user root`。部署请求本身已授权该范围，不另设重复审批。脚本安装固定版本并核对官方 SHA256，独立生成凭据，以低权限 systemd 服务运行三协议，配置防火墙，验证全新的 SSH 连接以及三种协议的 HTTPS 和出口 IP，再提交防火墙持久化。SSH root/密码/密钥登录设置保持原样。
3. 标准输出仅为摘要；`~/.config/proxy-vps-deploy/HOST-PORT/proxy.yaml` 是 JSON 格式的合法 YAML，含客户端凭据，权限 600。不要直接打印文件或远端 state.json。验证记录和备份不放进 skill。
4. 用户要求加入本机 Clash Verge 时，通过应用的“订阅→新建→Local→选择文件”导入独立配置。保持已有配置，按用户要求启用；不要退出/重启 Clash。用运行时 API 或 UI 确认实际选中节点、DNS、规则已生效。该脚本不会擅自覆盖现有分流或切换用户当前配置。
5. 本地独立内核验证只能证明各协议连通；启用后还需检查实际运行端口和浏览器资源。Google 首页有“页面显示但标签仍转圈”时，读取浏览器 Network 的耗时/失败请求，而非仅 curl 首页。

默认 Reality TCP 2053、AnyTLS TCP 2096、Hysteria2 UDP 443，额外仅放行实际 SSH 端口。未部署 XHTTP，无公开订阅/Web 管理端口。更换默认端口需要同步服务、客户端、白名单和验证。

## UDP/443 策略

默认 `--quic global`：**需要代理的 UDP/443 走 Hysteria2；国内/内网继续直连；TCP 按所选节点走 Reality**。强制代理域名（Cloudflare/OpenAI/Anthropic）也必须覆盖，不能被靠前规则绕过。其他 UDP 不强制改道。也提供 `--quic google`（仅 Google）和 `--quic off`。

这是当前线路的实测优化，不能宣称所有 Reality/UDP 都有故障，也不是加密强度排序。不能把“UDP/443 全局分流”误改成全局模式；这需要 **规则模式**。

## 安全和失败处理

- 服务端持久凭据只保存在 `/root/proxy-vps-deploy/state.json`，600；重跑保留身份和客户端凭据。遇到非本技能安装，勿因“相似”而迁移/换钥。
- Hysteria2 必须同时配置认证密码和 Salamander 混淆参数；AnyTLS/Hysteria2 固定新证书 SHA256 指纹，保持证书校验。不要为连通性而关闭校验。
- 防火墙是入站白名单，允许必要 ICMP/IPv6 邻居发现、DHCP 应答、已建立连接返回和本地 DNS。代理出站产生的高位 UDP socket 不是需要额外公开的端口。
- 新规则自带 10 分钟防火墙回滚；仅当新 SSH 登录和三协议验证均成功才取消回滚、持久化。失败后停止自动重试，读取本地 verification.json；不要擅自关闭防火墙或更换协议冒充成功。详情见 [故障与恢复](references/operations.md)。
- 只审计时不改变服务或防火墙；audit 仅在远端写入本技能的脚本目录。既有 SSH 密码登录是否保留遵从用户选择，不擅自限制到当前动态 IP 或代理出口 IP。

## 分享

读取 [分享与账号隔离](references/sharing.md)。向 Clash 用户提供配置文件可保留 UDP 分流；单节点链接/二维码只包含该节点。不要公开现有凭据，不自动上传订阅服务或第三方二维码网站；不要分享 SSH、服务端私钥或 state.json。

运行 `python3 scripts/export_share.py proxy.yaml --output-dir PRIVATE_DIR` 可离线导出 Reality 链接和可选二维码。该操作**复用现有节点身份**，不创建独立用户；实际分享前优先为接收方配置独立 UUID/认证密码并验证。不要声称仅导出链接就能独立撤销对方。

版本选择、验证范围和来源见 [故障与恢复](references/operations.md)。
