# Proxy VPS Deploy Skill

通过 SSH 部署个人代理 VPS 的 Codex skill，支持 **Debian 12 x86_64**。

- VLESS Reality、Hysteria2、AnyTLS，原生 systemd 低权限服务。
- 独立生成认证凭据；Hysteria2/AnyTLS 固定校验服务器证书指纹。
- nftables IPv4/IPv6 入站白名单，仅放行实际 SSH 和必要代理端口。
- 新规则带 10 分钟防火墙回滚；新 SSH 登录和三协议验证通过后才提交。
- 默认经代理的 UDP/443 走 Hysteria2，国内/内网直连，TCP 默认 Reality。
- 生成 Clash/Mihomo 客户端配置，可离线导出 Reality 链接和二维码。

## 安装为 Codex skill

```sh
git clone https://github.com/apptut/proxy-vps-deploy.git ~/.codex/skills/proxy-vps-deploy
```

如果目标目录已经存在，请先检查现有安装，避免覆盖。

在 Codex 中使用 `$proxy-vps-deploy`，提供主机地址、SSH 端口、root 用户名和密码或已有私钥即可。完整执行说明见 [SKILL.md](SKILL.md)。

## 命令行

本地需要 Python 3.9+、OpenSSH、curl 和 Mihomo（自动识别 macOS Clash Verge 内核）。

```sh
python3 scripts/deploy.py audit --host VPS_HOST --port 22 --user root
python3 scripts/deploy.py deploy --host VPS_HOST --port 22 --user root
```

密码使用隐藏输入，不写在命令参数中。也支持 `--identity PATH` 和受控 stdin。发现既有代理、业务监听或防火墙时拒绝直接覆盖。SSH 密码/密钥登录方式保持原样。

客户端配置保存在本机 `~/.config/proxy-vps-deploy/HOST-PORT/proxy.yaml`，含访问凭据，权限 600；不要提交、公开托管或上传此文件。服务端状态位于 `/root/proxy-vps-deploy/state.json`，也不属于仓库内容。

## 验证范围

```sh
python3 scripts/test_config.py
```

已校验生成配置的 Xray/sing-box/Mihomo 语法、nftables 规则语法、SSH 会话助手和三协议端到端验证器；尚未额外创建全新 VPS 演练完整安装与回滚流程。固定版本及恢复方式见 [operations.md](references/operations.md)。

## 分享

Clash 用户可导入客户端 YAML，以保留 UDP 分流；单个节点链接/二维码不包含完整分流。分享前建议创建独立用户，便于单独撤销。不要分享 SSH、服务器私钥或部署状态文件。见 [sharing.md](references/sharing.md)。

本仓库仅包含通用脚本、说明和动态生成的测试数据，不包含真实服务器地址、账号、密码、私钥、节点配置或部署日志。运行产生的数据应始终留在仓库之外。
