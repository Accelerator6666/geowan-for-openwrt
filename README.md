# GeoWAN for OpenWrt — GeoWAN Console v0.6.0（开发预览）

为 **OpenWrt 25.12 / firewall4 / nftables** 设计的独立 GeoIP 防护可视化和持久化伴侣，中文 LuCI 页面，无额外监听端口。

> **状态：v0.6.0 开发预览；Sensitive Port Guard 尚未完成目标路由器实机验收。请先备份，按只读预检和分阶段测试流程部署。**
> 原有 GeoWAN GeoIP 过滤与 DNAT 保持不变。v0.6.0 新增独立的 log/counter-only 观察链 `geo_guard_forward`，不改变 ACCEPT/DROP/REJECT 决策，不启用自动封禁。

## 功能

- LuCI → 服务 → **GeoWAN 安全面板**：当前被阻断 IP、包计数、可选时间范围的拦截日志趋势、来源 IP、国家、ASN、目标端口、协议、最近事件和过期时间。
- SQLite 持久保存被封锁 IP 和最近 30 天的**采样**内核日志；v0.2 快速监控每 5 秒采样计数器、每 15 秒盘点动态集合和扫描日志；每 5 分钟保留一次恢复/全量对账任务。
- GeoIP 数据库更新脚本已提供，但**不会自动排程**：首次下载需要手动执行并验证，后续月度自动更新将在单独验收后启用。它只更新离线 MMDB 文件，不修改 nftables 或 CN 前缀集合。
- IPv4/IPv6 分别维护统计；前端只读，走现有 LuCI/rpcd 身份验证和单一状态 JSON 文件；LuCI 每 5 秒刷新。
- v0.6.0 Guard 额外要求可读取 `uci export firewall`、`nft list chain inet fw4 dstnat_wan` 和 `ubus network.interface.wan status`；通过本机 GeoIP 缓存区分国内/海外来源，不调用公网 API。Guard 配置保存在 `/etc/geowan-console/guard.json`，默认 `enabled=true`、`mode=observe`、每服务每秒最多 2 条日志、burst 10。
- 可选离线 DB-IP Lite MMDB 归属查询：国家、洲、地区/城市、ASN 和网络组织；数据在本机查询，不调用逐 IP 公网 API。
- LuCI 提供任意公网 IPv4/IPv6 查询入口，通过只读 rpcd ubus 方法查询本地 MMDB 或已缓存结果，不开放新的 HTTP/TCP/UDP 端口。
- v0.2.2 增加黑名单分页、筛选、IP 详情及采样事件查询；v0.3.0 增加最近 1 小时、24 小时、7 天、30 天的只读趋势分析，并提供首版黑名单查询界面；v0.4.0 优化黑名单管理体验，增加 20/50/100 条分页、首页/末页导航、首次发现/最近日志样本/剩余封禁时间列、详情关闭和过期状态提示；所有 RPC 方法均为只读，并受 LuCI ACL 控制。
- v0.5.0 增加只读来源 IP 画像、ASN / 网络组织画像和跨来源关联线索；支持 1 小时、24 小时、7 天、30 天范围。v0.5.1 修复滚动窗口导致的时间桶漂移，统一使用固定 UTC Unix epoch 时间边界；关联簇增加国家/地区、ASN 数量及分布，并返回最多 100 个来源 IP 的明细；来源列表或超过 50 项的国家 / ASN 分布会明确标记截断。评分不是威胁情报信誉分，不将国家、城市或 ASN 名称作为恶意证据，不触发防火墙动作。
- v0.6.0 新增 Sensitive Port Guard：从本机 UCI redirect 与运行时 `dstnat_wan` 交叉发现公网服务，识别地址族、TCP/UDP、公网原始端口、DNAT 后端和映射冲突；通过独立 `geo_guard_forward` 链观察所有 WAN 来源访问公网 DNAT 服务的 NEW/DNAT 流量，按公网原始端口归属，保存独立 `guard_events` 样本，并通过本地 GeoIP 缓存区分国内/海外来源。LuCI 提供服务资产、端口排行、来源排行、端口筛选和最近事件。默认仅观察，日志限速，样本不是完整连接数；冲突映射不生成采集规则。
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

开发分支 `develop-v0.5.1` 从 `develop-v0.5.0` 继续开发。v0.5.1 不改变 SQLite schema，不新增写入型 RPC；保留只读 `lookup`、`list_bans`、`get_ban`、`analytics`、`source_profile`、`asn_profile` 和 `correlations`。画像及关联模块统一使用固定 UTC Unix epoch 时间桶，避免滚动查询窗口改变历史分组。黑名单界面支持 20/50/100 条每页、首页/末页导航，并展示首次发现、最近发现、最近日志样本、剩余封禁时间和日志样本数；剩余封禁时间不足 1 小时时显示提醒，详情面板可关闭，并防止较早返回的详情请求覆盖用户刚选中的 IP。趋势时间范围为 1 小时（5 分钟桶）、24 小时（小时桶）、7 天和 30 天（日桶）；来源国家、ASN、端口、协议和来源 IP 均按已采集的内核日志样本统计。由于内核日志限速，样本数不代表完整连接数或攻击总量。黑名单国家/ASN 排行仍按当前活跃封禁 IP 去重统计，两种口径在界面中分开标注。该版本不提供手动封禁/解封，不修改防火墙规则。首次安装不会自动下载约 140 MB 的 GeoIP 数据库，也不会自动启用月度更新。

## 第一阶段：只读预检

先在路由器执行：

    cd /root/geowan-source
    sh preflight.sh

脚本只读取系统、nftables 对象、JSON 集合样本、日志和磁盘信息，并执行 `fw4 check` 与 Guard 规则 `nft -c -f -` 语法预检；**不会 reload 防火墙、应用/修改 nftables 规则、写数据库或执行 GeoIP 更新**。如输出 FAIL，先停止并排查，不要安装。

## 安装（预检通过后）

    apk update
    apk add python3 python3-sqlite3 python3-maxminddb git
    cd /root
    git clone --depth 1 --branch develop-v0.6.0 https://github.com/Accelerator6666/geowan-for-openwrt.git geowan-source
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
4. v0.6.0 Guard 只在 `inet fw4` 中创建独立的 `geo_guard_forward` base chain（forward priority -2），只对 WAN 入站、`ct state new`、`ct status dnat` 的流量执行 counter 和限速 log；按 IPv4/IPv6 与 conntrack 原始公网端口分别匹配。该链不插入现有 `geo_wan_forward`/`geo_filter`，不改变现有链、集合、DNAT 或转发 verdict。国家/地区仅用于归属分析，不作为可信或恶意判定；采集点位于 GeoWAN 国家过滤之前，因此样本可能随后被既有规则丢弃。
5. 映射冲突的服务不会生成 Guard 采集规则。若 WAN 设备无法识别、运行时 DNAT 链不可读或 Guard 链签名不匹配，Guard 会报告异常并停止更新，不会猜测规则或执行封禁。
6. 卸载会在确认链的类型、hook、priority 和 accept policy 符合 Guard 标识后删除 `geo_guard_forward`；`guard.json` 和 SQLite 数据保留。
7. 黑名单恢复依赖已存在且未过期的 nft 动态集合；若规则缺失，会跳过并报告，不会建立替代防火墙。

## 卸载

    cd /root/geowan-source
    sh uninstall.sh
    # 如确认不再需要审计数据：
    # sh uninstall.sh --purge-data

卸载不会改动现有 GeoWAN 或其他防火墙规则。

## 测试

    python3 -m unittest discover -s tests -v
    python3 -m py_compile agent/*.py rpcd/geowan
    sh -n install.sh uninstall.sh scripts/*.sh preflight.sh
    node --check luci/overview.js


## v0.5.1 固定时间桶与跨 ASN 关联

- 时间桶按 Unix epoch 固定边界对齐：5 分钟、1 小时或 1 天；查询窗口只决定纳入哪些事件，不再作为时间桶起点。
- `source_profile` 的活跃时间桶、`asn_profile` 内部关联和全局 `correlations` 使用同一时间边界定义。
- 关联簇按目标 IP、端口、协议和固定时间桶分组；来源 IP 总数始终统计全部匹配来源。
- 每个关联簇增加已识别国家/地区数、ASN 数、国家分布、ASN / 网络组织分布及 GeoIP 未识别来源数。
- 每个关联簇最多返回 100 个来源 IP，附带国家和 ASN 信息；若超过上限，`sources_truncated` 明确为 true，避免把截断列表误认为完整列表。
- 国家和 ASN 数量均按不同来源 IP 去重，不按日志样本数计算；未知 GeoIP 来源仍计入来源 IP 总数。
- 时间桶显示的是固定桶起点，统计仅覆盖所选查询窗口内的样本；查询窗口首尾可能出现部分时间桶。
- 不新增数据库表或索引，不改变防火墙规则、nftables 集合、监听端口、代理分流或现有采集行为。

v0.5.1 回归测试使用已在目标路由器只读核对的案例：`112.82.232.30:40163/UDP`，27 个不同来源 IP、20 个国家/地区、27 个 ASN。测试使用合成 SQLite 数据，不包含生产路由器日志或用户 IP 清单。

## v0.5.0 画像与评分说明

- 来源 IP 画像按所选时间范围聚合 `events`，最多返回 10 个目标端口、10 个目标地址、8 个协议和 30 条事件样本。
- ASN 画像只纳入当前 GeoIP 数据库版本中成功识别 ASN 的事件来源；来源 IP 列表最多 20 条，端口/目标地址各最多 10 条，协议最多 8 条。
- 关联簇按目标 IP、目标端口、协议和时间桶聚合。全局关联至少需要 3 个不同来源 IP；单 ASN 内关联至少需要 2 个不同来源 IP。代表性来源最多显示 10 个。
- 来源观察评分由重复样本、目标端口多样性、目标地址多样性、跨时间桶重复出现和最近活动时间组成。样本少于 3 条时不评分，显示“证据不足”。
- 评分不使用国家、城市、ASN 名称或云服务商身份作为恶意证据；不等同于威胁情报或攻击者归因，不参与防火墙决策。
- 内核日志存在限速，所有画像、评分、排行和关联结果均是已采集样本的观察结果，不代表完整攻击总量。

## 独立仓库说明

此项目的正式仓库为 [Accelerator6666/geowan-for-openwrt](https://github.com/Accelerator6666/geowan-for-openwrt)。`main` 保留已在 OpenWrt 实测的旧稳定基线；`develop-v0.5.0`、`develop-v0.5.1` 保留对应开发预览；`develop-v0.6.0` 增加 Sensitive Port Guard，尚未完成目标设备验收。迁移后的源代码位于仓库根目录，无需进入 `projects/geowan-console` 子目录。
