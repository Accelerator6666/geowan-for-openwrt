'use strict';
'require view';
'require rpc';
'require poll';
'require dom';

var readStatus = rpc.declare({
    object: 'file', method: 'read', params: [ 'path' ],
    expect: { data: '' }
});

function statusFromRpc(value) {
    if (typeof value == 'string') return JSON.parse(value);
    if (value && typeof value.data == 'string') return JSON.parse(value.data);
    throw new Error('未收到有效的 GeoWAN 状态');
}

function timeString(epoch) {
    return epoch ? new Date(epoch * 1000).toLocaleString() : '—';
}

function durationString(seconds) {
    seconds = Math.max(0, Math.floor(Number(seconds) || 0));
    if (!seconds) return '已过期';
    var days = Math.floor(seconds / 86400);
    var hours = Math.floor((seconds % 86400) / 3600);
    return days ? days + ' 天 ' + hours + ' 小时' :
        hours ? hours + ' 小时' : Math.ceil(seconds / 60) + ' 分钟';
}

function card(label, value, note) {
    return E('div', { 'class': 'gw-card' }, [
        E('div', { 'class': 'gw-label' }, label),
        E('div', { 'class': 'gw-value' }, String(value)),
        E('div', { 'class': 'gw-note' }, note || '')
    ]);
}

function table(headers, rows) {
    return E('table', { 'class': 'table gw-table' }, [
        E('thead', {}, E('tr', {}, headers.map(function(h) {
            return E('th', {}, h);
        }))),
        E('tbody', {}, rows.length ? rows.map(function(cells) {
            return E('tr', {}, cells.map(function(c) {
                return E('td', {}, c == null || c === '' ? '—' : String(c));
            }));
        }) : E('tr', {}, E('td', { 'colspan': headers.length }, '暂无记录')))
    ]);
}

function panel(title, body) {
    return E('section', { 'class': 'gw-panel' }, [
        E('h3', {}, title), body
    ]);
}

function banRow(item) {
    return [item.ip, item.country_name || item.country_code || '待识别',
        (item.proto || '—') + '/' + (item.trigger_port || '—'),
        timeString(item.first_seen), timeString(item.expires_at)];
}

function draw(data) {
    var runtime = data.guard_enforcement || {};
    var cn = data.cn_honeypot || {};
    var cnBans = (data.cn_honeypot_bans ||
        (data.guard_blocklist || []).filter(function(item) {
            return item.reason == 'cn_honeypot';
        })).slice(0, 30).map(banRow);
    var oldBans = (data.guard_blocklist || []).filter(function(item) {
        return item.reason != 'cn_honeypot';
    }).slice(0, 10).map(banRow);
    var geoBans = (data.blacklist || []).slice(0, 20).map(function(item) {
        return [item.ip, 'IPv' + item.family,
            item.country || item.country_code || '待识别',
            timeString(item.expires)];
    });
    var counters = data.counters || {};
    var groups = runtime.honeypot_groups || [];
    var skipped = runtime.skipped_in_use || [];
    var foreignDrops = (Number(counters.black4) || 0) +
        (Number(counters.black6) || 0) + (Number(counters.geo4) || 0) +
        (Number(counters.geo6) || 0);
    var running = runtime.mode == 'enforce' && runtime.chain_installed;
    var stateText = running ? 'CN 蜜罐运行中' :
        runtime.mode == 'observe' ? 'CN 蜜罐仅观察' :
        runtime.mode == 'degraded' ? '蜜罐规则异常' : '蜜罐未启用';
    var healthy = data.status == 'ok' && runtime.mode != 'degraded';

    return E('div', { 'class': 'gw-app' }, [
        E('link', { 'rel': 'stylesheet', 'href': L.resource('geowan/geowan.css') }),
        E('div', { 'class': 'gw-heading' }, [
            E('div', {}, [
                E('h2', {}, 'GeoWAN 安全防护'),
                E('p', {}, 'CN 蜜罐、海外来源和历史封禁分别统计')
            ]),
            E('span', { 'class': 'gw-status ' + (healthy ? 'ok' : 'warn') },
                healthy ? '防护状态正常' : '请检查防护状态')
        ]),
        E('div', { 'class': 'gw-cards' }, [
            card('CN 蜜罐封禁', cn.active_ips || 0, '当前已记录的 IP'),
            card('CN 近 24 小时', cn.new_ips_24h || 0, '新记录的 IP'),
            card('海外黑名单', data.active_bans || 0, '当前活跃 IP'),
            card('海外丢弃包', foreignDrops, '本次规则加载以来')
        ]),
        panel('CN 来源与蜜罐状态', E('div', {}, [
            E('div', { 'class': 'gw-guard-status ' +
                (running ? 'gw-guard-state-ok' : 'gw-guard-state-warn') }, [
                E('strong', {}, stateText),
                E('span', {}, ' · 覆盖 ' + (runtime.honeypot_ports || []).length + ' 个端口'),
                E('span', {}, ' · 封禁 ' + durationString(runtime.ban_seconds || 604800)),
                E('span', {}, ' · 最近命中 ' + timeString(cn.last_hit))
            ]),
            E('p', { 'class': 'gw-muted' },
                'CN 归属按 geo_cn 网段集合判断；下表国家名称来自可选 GeoIP，可能有差异。'),
            E('div', { 'class': 'gw-category-grid' }, groups.length ?
                groups.map(function(group) {
                    return E('div', { 'class': 'gw-category' }, [
                        E('strong', {}, group.name),
                        E('span', {}, (group.ports || []).map(function(port) {
                            return port.port + '/' + port.proto.toUpperCase();
                        }).join(' · '))
                    ]);
                }) : E('p', {}, '尚无启用的蜜罐端口')),
            skipped.length ? E('p', { 'class': 'gw-error' },
                '以下端口正在使用，已跳过：' + skipped.map(function(row) {
                    return row[2] + '/' + row[1].toUpperCase();
                }).join('、')) : E('span'),
            E('p', { 'class': 'gw-muted' },
                '31080、58964、20443 是保留的 NAT 端口，不触发蜜罐且不受 Guard 封禁。'),
            E('h4', {}, '最近 CN 蜜罐封禁'),
            table(['来源 IP', '归属地', '协议/端口', '首次发现', '到期时间'], cnBans),
            runtime.last_error ? E('p', { 'class': 'gw-error' },
                '规则错误：' + runtime.last_error) : E('span'),
            E('p', { 'class': 'gw-muted' },
                '命中后由防火墙内核直接丢弃并加入封禁集合；页面记录依赖日志同步。')
        ])),
        panel('海外来源', E('div', {}, [
            E('p', { 'class': 'gw-muted' },
                '非 CN WAN 来源继续由原有 GeoWAN 规则拒绝。最近 20 条黑名单：'),
            table(['来源 IP', '地址族', '归属地', '封禁到期'], geoBans)
        ])),
        panel('旧版 Guard 封禁', E('div', {}, [
            E('p', { 'class': 'gw-muted' },
                '仍有 ' + (cn.legacy_active_ips || 0) +
                ' 个旧规则封禁 IP，按原到期时间保留；不计入 CN 蜜罐指标。'),
            table(['来源 IP', '归属地', '协议/端口', '首次发现', '到期时间'], oldBans)
        ])),
        (data.errors || []).length ?
            E('p', { 'class': 'gw-error' }, data.errors.join('；')) : E('span'),
        E('div', { 'class': 'gw-footer' }, [
            '更新：' + timeString(data.updated) + ' · ',
            '日志与 IP 归属存在延迟；不将地理位置等同于恶意证据。',
            data.geoip && data.geoip.enabled ?
                E('a', { 'href': data.geoip.attribution_url, 'target': '_blank',
                    'rel': 'noopener noreferrer' }, 'IP Geolocation by DB-IP') : ''
        ])
    ]);
}

return view.extend({
    load: function() {
        return readStatus('/tmp/geowan-console/status.json').then(statusFromRpc);
    },
    render: function(data) {
        var root = E('div', {}, draw(data));
        poll.add(function() {
            return readStatus('/tmp/geowan-console/status.json').then(function(next) {
                dom.content(root, draw(statusFromRpc(next)));
            }).catch(function() {
                /* Preserve the last snapshot during a temporary RPC outage. */
            });
        }, 5);
        return root;
    },
    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
