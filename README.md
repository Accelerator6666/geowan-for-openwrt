# GeoWAN for OpenWrt — CN 蜜罐与黑名单

面向 OpenWrt 25.12.x、firewall4 和 nftables。项目沿用已有的 GeoWAN 地域过滤规则：非 CN WAN 来源在 INPUT/FORWARD 被拒绝并进入 `geo_black4/6`；CN 来源访问明确配置的蜜罐端口时，由 nftables 在首个新建包上立即拒绝并加入 `geo_guard_ban4/6`。LuCI 分开显示 CN 蜜罐、海外来源与旧版封禁。

## 当前策略

- 默认蜜罐按 Windows、Linux、群晖、威联通、Docker/容器及媒体服务分组，端口见 [示例配置](enforcement.example.json)。运行时自动跳过正在监听、有 WAN 端口映射或显式 WAN 放行规则的端口，并在预检与页面中列出；部署前仍需核对业务。目标设备正在监听的 22、80、443 没有被列为蜜罐。
- 默认蜜罐模式为 `observe`。确认端口无业务后，才在 `/etc/geowan-console/enforcement.json` 中改为 `enforce`。
- 31080、58964、20443 是保留的 NAT 业务端口，不参与蜜罐触发，也绕过 Guard 黑名单规则。已有 GeoWAN 地域过滤和其他防火墙规则仍按原配置工作。
- 蜜罐只按已有的 `geo_cn4/6` nftables 集合识别 CN 来源，不依赖离线 MMDB 的查询结果。CN 集合表示网段归属，并不能证明访问者的真实位置。
- Guard 封禁默认 7 天，后台把 nftables 动态集合持久化到 SQLite，并在 firewall4 重载或重启后恢复未到期记录。旧版 v0.7 产生的封禁保留到原到期时间。
- 页面分别统计当前 CN 蜜罐 IP、近 24 小时新记录 CN IP、海外黑名单和旧版封禁；CN 指标依赖日志同步，可能落后于内核封禁集合。其他扫描和渗透行为只有出现明确可验证的触发信号才能自动封禁。单次访问真实业务端口不构成蜜罐命中。

原来的来源画像、ASN 关联和多维告警代码仍在仓库中，暂不出现在简化后的首页，也不参与封禁决策。旧配置中的 `sensitive_ports`、`protect_all_active_redirects`、`auto_detect_rdp`、`auto_detect_sslvpn` 不再生成封禁规则。

## 运行要求

- 现有 `/etc/nftables.d/90-geo-wan.nft` 已提供 `geo_cn4/6`、`geo_black4/6`、`geo_filter`、`geo_wan_input` 和 `geo_wan_forward`。
- LuCI、rpcd、Python 3 与 `python3-sqlite3`。`python3-maxminddb` 和 DB-IP Lite 是可选的归属地补充。
- 路由器有足够空间保存 `/etc/geowan-console/telemetry.sqlite3`。

## 安装与检查

在路由器备份现有防火墙和 `/etc/geowan-console` 后，下载本分支，先执行 `sh preflight.sh`。预检会检查必需的 nftables 对象、当前端口映射并对候选规则执行 `nft -c`，不应用新规则。只有预检通过再执行 `sh install.sh`。安装器保留已有的 `enforcement.json`；迁移旧版本时应对照 [示例配置](enforcement.example.json)明确设置 `honeypot_ports`。

安装后检查：

```sh
cat /tmp/geowan-console/status.json
nft list chain inet fw4 geo_guard_enforce_input
nft list chain inet fw4 geo_guard_enforce_forward
nft list set inet fw4 geo_guard_ban4
logread | grep GEOWAN_HONEY | tail
```

LuCI 页面位于“服务 → GeoWAN 安全面板”。前端通过现有 LuCI/rpcd 读取状态，不增加监听端口。

## 验收重点

1. 蜜罐端口没有 WAN 监听或 DNAT；31080、58964、20443 的现有映射保持原样。
2. CN 来源命中蜜罐：首包 DROP，来源进入 `geo_guard_ban4/6`，随后出现在 LuCI 记录中。
3. 非 CN 来源：继续由现有 `geo_filter` 拒绝并进入 `geo_black4/6`。
4. 正常访问业务端口不会因为端口属于 DNAT 或“常见敏感端口”而触发新封禁。
5. firewall4 重载后，未到期的 Guard 封禁可以恢复；例外业务端口不受 Guard 封禁规则影响。

本地检查：`python3 -m unittest discover -s tests -v`、`node --check luci/overview.js`、`sh -n install.sh preflight.sh scripts/*.sh`。
