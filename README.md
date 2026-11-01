# GeoWAN for OpenWrt — GeoWAN Console v0.4.0

为 **OpenWrt 25.12 / firewall4 / nftables** 设计的独立 GeoIP 防护可视化和持久化伴侣，中文 LuCI 页面，无额外监听端口。

> **状态：v0.4.0 已在用户的 OpenWrt 25.12.3 环境完成基础功能与分页实机验收。其他设备安装前仍需自行预检和备份。**
> 该组件只观测已经存在的 GeoWAN nftables 规则，不会修改 WAN 防火墙策略、DNAT、PPPoE、daed 或代理分流。

## 功能

- LuCI → 服务 → **GeoWAN 安全面板**：当前被阻断 IP、包计数、可选时间范围的拦截日志趋势、来源 IP、国家、ASN、目标端口、协议、最近事件和过期时间。
- SQLite 持久保存被封锁 IP 和最近 30 天的**采样**内核日志；v0.2 快速监控每 5 秒采样计数器、每 15 秒盘点动态集合和扫描日志；每 5 分钟保留一次恢复/全量对账任务。
- GeoIP 数据库更新脚本已提供，但**不会自动排程**：首次下载需要手动执行并验证，后续月度自动更新将在单独验收后启用。它只更新离线 MMDB 文件，不修改 nftables 或 CN 前缀集合。
- IPv4/IPv6 分别维护统计；前端只读，走现有 LuCI/rpcd 身份验证和单一状态 JSON 文件；LuCI 每 5 秒刷新。
- 可选离线 DB-IP Lite MMDB 归属查询：国家、洲、地区/城市、ASN 和网络组织；数据在本机查询，不调用逐 IP 公网 API。
- LuCI 提供任意公网 IPv4/IPv6 查询入口，通过只读 rpcd ubus 方法查询本地 MMDB 或已缓存结果，不开放新的 HTTP/TCP/UDP 端口。
- v0.2.2 增加黑名单分页、筛选、IP 详情及采样事件查询；v0.3.0 增加最近 1 小时、24 小时、7 天、30 天的只读趋势分析，并提供首版黑名单查询界面；v0.4.0 优化黑名单管理体验，增加 20/50/100 条分页、首页/末页导航、首次发现/最近日志样本/剩余封禁时间列、详情关闭和过期状态提示；所有 RPC 方法均为只读，并受 LuCI ACL 控制。
- 不在 LAN/WAN 开放新端口，不将日志发布到公网，不需要 Node/npm、Docker 或独立 Web 服务。

## 运行要求

- OpenWrt 25.12.x、firewall4/nftables、LuCI、rpcd。
- 已部署 /etc/nftables.d/90-geo-wan.nft，包含：
  - geo_cn4 / geo_cn6
  - geo_black4 / geo_black6 动态 set
  - geo_filter、geo_wan_input、geo_wan_forward
  - 内核日志前缀 GEOWAN4 / GEOWAN6
- Python 3 + SQLite 模块（OpenWrt 25.12 apk 包为 python3 和 python3-sqlite3）。
- GeoIP 为可选功能：安装 `python3-maxminddb` 后运行 DB-IP Lite MMDB 更新器；缺少 reader 或数据库时不影响拦截与基础监控。
- 数据库 /etc/geowan-console/telemetry.sqlite3，目录权限 0700；状态文件 /tmp/geowan-console/status.json。

稳定分支 `main` 基于已实机验收的 v0.3.0，不改变 SQLite schema，不新增写入型 RPC；继续复用只读 `list_bans`、`get_ban` 和 `analytics` API。黑名单界面支持 20/50/100 条每页、首页/末页导航，并展示首次发现、最近发现、最近日志样本、剩余封禁时间和日志样本数；剩余封禁时间不足 1 小时时显示提醒，详情面板可关闭，并防止较早返回的详情请求覆盖用户刚选中的 IP。趋势时间范围为 1 小时（5 分钟桶）、24 小时（小时桶）、7 天和 30 天（日桶）；来源国家、ASN、端口、协议和来源 IP 均按已采集的内核日志样本统计。由于内核日志限速，样本数不代表完整连接数或攻击总量。黑名单国家/ASN 排行仍按当前活跃封禁 IP 去重统计，两种口径在界面中分开标注。该版本不提供手动封禁/解封，不修改防火墙规则。首次安装不会自动下载约 140 MB 的 GeoIP 数据库，也不会自动启用月度更新。

## 第一阶段：只读预检

先在路由器执行：

    cd /root/geowan-source
    sh preflight.sh

脚本只读取系统、nftables 对象、JSON 集合样本、日志和磁盘信息，并执行 fw4 check；**不会 reload 防火墙、修改 nftables、写数据库或执行 GeoIP 更新**。如输出 FAIL，先停止并排查，不要安装。

## 安装（预检通过后）

    apk update
    apk add python3 python3-sqlite3 python3-maxminddb git
    cd /root
    git clone --depth 1 --branch main https://github.com/Accelerator6666/geowan-for-openwrt.git geowan-source
    cd /root/geowan-source
    sh preflight.sh
    sh install.sh

打开 LuCI：**服务 → GeoWAN 安全面板**。

首次安装后如需启用国家/城市/ASN 查询，执行：

    /usr/libexec/geowan-console/update-geoip.sh 2026-11

数据库来自 [DB-IP Lite](https://db-ip.com/db/lite.php)，按月发布，采用 CC BY 4.0；面板会显示要求的 DB-IP 署名。更新脚本先校验 gzip 和 MMDB 文件，再通过版本目录与原子 symlink 切换数据库。尚未安排自动更新任务。

安装会先检查所需 nftables 对象及 fw4 check。安装后启动 procd 监管的快速监控：计数器每 5 秒采样，动态集合与日志每 15 秒扫描；原有每 5 分钟恢复/全量对账任务保留。GeoIP 自动更新仍关闭；首次数据库下载和每月更新需手动执行，实机验证后再考虑排程。

## 验收命令

    /usr/bin/python3 /usr/libexec/geowan-console/agent.py collect
    /usr/bin/python3 /usr/libexec/geowan-console/agent.py restore
    /usr/bin/python3 /usr/libexec/geowan-console/agent.py lookup 8.8.8.8
    cat /tmp/geowan-console/status.json
    nft list set inet fw4 geo_black4
    grep geowan-console /etc/crontabs/root
    logread | grep GEOWAN | tail

## 数据含义

- **丢弃包数**：当前 nftables 规则加载周期内的 counter；firewall4 reload/reboot 会归零。
- **事件/来源排行/趋势**：仅来自 GEOWAN4 / GEOWAN6 内核日志的样本。现有规则使用全局日志限速，不会完整记录每个 IP 和每次包命中；任何基于它的统计都不是攻击总量。
- **动态黑名单**：当前拒绝的非 CN 来源 IP，不等于已经证实为恶意攻击者。
- **GeoIP**：离线数据库的归属结果是网络注册/分配信息，不是人员真实所在地；DB-IP Lite 覆盖和准确度低于商业版；城市级定位应视为估算。香港/澳门/台湾网段在默认 CN 表外。
- **IPv6**：设备没有 IPv6 WAN 默认路由时，可能没有实际 IPv6 入站流量。

## 安全边界

1. 不要把 LuCI 面板或状态文件直接暴露公网。仅通过 LAN 或 VPN 管理。
2. RDP、SSL VPN、JumpServer 的端口映射由现有防火墙配置管理；本项目不改动。
3. SQLite 包含来源 IP、时间、目的 IP/端口等敏感运维日志，不要上传公开 GitHub。
4. 黑名单恢复依赖已存在且未过期的 nft 动态集合；若规则缺失，会跳过并报告，不会建立替代防火墙。

## 卸载

    cd /root/geowan-source
    sh uninstall.sh
    # 如确认不再需要审计数据：
    # sh uninstall.sh --purge-data

卸载不会改动现有 GeoWAN 或其他防火墙规则。

## 测试

    python3 -m unittest discover -s tests -v
    sh -n install.sh uninstall.sh scripts/*.sh preflight.sh
    node --check luci/overview.js

## 仓库与开发分支

此仓库是 GeoWAN for OpenWrt 的独立代码库。`main` 保存实机验证的 v0.4.0；`develop-v0.5.0` 用于来源 IP / ASN 画像及关联分析，未通过实机验收前不建议在生产路由器部署。
