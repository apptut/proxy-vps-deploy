# 版本、验证和恢复

## 来源与版本

原生 systemd 配方来自本次新旧 VPS 实测，不是直接运行第三方全量安装器。参考 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 的 Reality 部署，使用 Xray 26.3.27、sing-box 1.14.2。下载地址和 SHA256 固定在 `scripts/proxy_config.py`，来自官方 GitHub release asset 的 digest；新增支持架构或更新版本必须重新取官方发布校验值，并做服务端/实际 Mihomo 端到端验证。

- [Xray 官方 release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
- [sing-box 官方 release](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2)
- [Mihomo TLS 指纹验证](https://wiki.metacubex.one/config/proxies/tls/)
- [Hysteria2 客户端认证、混淆、TLS](https://hysteria.network/docs/advanced/Full-Client-Config/)
- [nftables 服务端白名单示例](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_server)

固定版本为可复现基线，不意味着永远最新或没有漏洞。技能执行时如有安全更新需求，查询官方公告评估兼容性；不要自动使用 latest 绕过固定 SHA256。Xray Reality 与 Mihomo 有版本兼容性边界，升级必须实际验证。

## 预期网络边界

| 入站 | 默认 |
|---|---|
| TCP 实际 SSH 端口 | 保留 |
| TCP 2053 | Reality |
| TCP 2096 | AnyTLS |
| UDP 443 | Hysteria2 |
| 其他未请求入站 | 丢弃 |

IPv4/IPv6 共用 inet 规则。127.0.0.53/54:53 只供本地解析；禁用 LLMNR/mDNS 后 5355 不再监听。ICMP/ICMPv6 及 DHCP 客户端响应属于网络基础流量，不是额外公开的应用服务。forward 默认丢弃，出站放行；本配方是用户态代理，不是内核转发路由器。

外部验证最好从另一台授权主机检查 TCP 开放/拦截，不应使用“经这台 VPS 的代理访问它自身”冒充外部扫描。UDP443 以真实 Hysteria2 会话/HTTPS 成功验证，不以 UDP nc 无响应断言端口关闭。无外部 IPv6 链路时只能报告 IPv6 规则检查，不能报告 IPv6 外部验证成功。

## 回滚事务

候选规则先通过 `nft -c`。旧运行规则及 `/etc/nftables.conf` 保存在 `/root/proxy-vps-deploy/firewall-backup/`。`proxy-vps-firewall-rollback.timer` 在 10 分钟后自动恢复这两处防火墙；**不回滚 apt、代理服务、凭据或 resolver 配置**，不能称作整机事务。

修复失败后，先查看 timer 是否已触发及 `pending-firewall` 是否存在，不覆盖未完成事务。必要时通过仍可用的 SSH 或供应商控制台执行：

```sh
/root/proxy-vps-deploy/rollback-firewall.sh
systemctl stop proxy-vps-firewall-rollback.timer
```

通过同一套 deploy 脚本重跑可保留凭据、重新应用并验证防火墙。不要单独运行 commit 来跳过新 SSH 和协议验证。若需人工恢复，完整验证后才可执行远端 `deploy_remote.py commit`。

## 已知排障点

- Hysteria2 超时而 TCP 协议正常：先对比服务端 obfs.type/password 和客户端 obfs/obfs-password，再抓 UDP 报文；本次曾因遗漏 Salamander 参数失败。
- 地址迁移：不要复制旧机 sendThrough / inet4_bind_address；这些会报 bind: cannot assign requested address。此技能不硬编码出站本机地址。
- 证书变化：重新计算证书 DER 的 SHA256，原子更新对应客户端 fingerprint；不改 skip-cert-verify。
- Google 标签页加载慢：实际浏览器曾测到主脚本 8.8 秒、Load 14.27 秒；将经代理 UDP443 交给 Hysteria2 后两次 Load 2.33/1.86 秒。这是一次线路对照，非通用协议性能结论。
- 新机验收包含服务启用/活动状态、语法检查、新 SSH 连接、三协议 HTTPS204/出口 IP；浏览器 HTTP3/Google 登录态资源仍需要单独复核。云厂商安全组不在 SSH 主机规则的覆盖范围。

## 本次封装校验范围

已在现有兼容 VPS 上使用只写临时文件的方式，调用固定版本 Xray/sing-box 验证生成的服务端配置，调用 `nft -c` 验证候选规则；未在校验过程中替换现有服务或规则。新的 SSH 密码会话助手及三协议端到端验证器也在现有 VPS 上实测通过。离线回归检查覆盖独立凭据、证书/混淆参数同步、直连和 UDP 规则顺序、端口白名单、分享链接不包含服务端私钥。

未额外购买/创建全新 VPS 跑完整的 apt→部署→回滚流程，因此不得把这些校验描述成已做全新机器整流程演练。
