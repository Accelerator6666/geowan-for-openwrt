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

function draw(data) {
    var runtime = data.guard_enforcement || {};
    var guardBans = (data.guard_blocklist || []).map(function(item) {
        return [
            item.ip,
            item.country_name || item.country_code || '待识别',
            item.reason == 'cn_honeypot' ? 'CN 蜜罐' : '旧版规则',
            (item.proto || '—') + '/' + (item.trigger_port || '—'),
            timeString(item.first_seen),
            timeString(item.expires_at)
        ];
    });
    var geoBans = (data.blacklist || []).slice(0, 20).map(function(item) {
        return [item.ip, 'IPv' + item.family,
            item.country || item.country_code || '待识别',
            timeString(item.expires)];
    });
    var counters = data.counters || {};
    var honeypots = runtime.honeypot_ports || [];
    var dropped = (counters.black4 || 0) + (counters.black6 || 0) +
                  (counters.geo4 || 0) + (counters.geo6 || 0);
    var running = runtime.mode == 'enforce' && runtime.chain_installed;
    var stateText = running ? 'CN 蜜罐封禁运行中' :
        runtime.mode == 'observe' ? 'CN 蜜罐观察模式' :
        runtime.mode == 'degraded' ? '蜜罐规则异常' : '蜜罐未启用';

    return E('div', { 'class': 'gw-app' }, [
        E('link', { 'rel': 'stylesheet', 'href': L.resource('geowan/geowan.css') }),
        E('div', { 'class': 'gw-heading' }, [
            E('div', {}, [
                E('h2', {}, 'GeoWAN 安全防护'),
                E('p', {}, '海外来源拦截 · CN 蜜罐封禁')
            ]),
            E('span', { 'class': 'gw-status ' + (data.status == 'ok' ? 'ok' : 'warn') },
                data.status == 'ok' ? '采集正常' : '采集异常')
        ]),
        E('div', { 'class': 'gw-cards' }, [
            card('海外黑名单', data.active_bans || 0, '当前活跃 IP'),
            card('Guard 封禁', runtime.active_bans || 0, '包含未到期的旧版记录'),
            card('已丢弃包', dropped, '本次规则加载以来'),
            card('最近更新', timeString(data.updated), stateText)
        ]),
        panel('CN 蜜罐', E('div', {}, [
            E('div', { 'class': 'gw-guard-status ' +
                (running ? 'gw-guard-state-ok' : 'gw-guard-state-warn') }, [
                E('strong', {}, stateText),
                E('span', {}, ' · 端口：' +
                    (honeypots.length ? honeypots.join('、') : '未配置')),
                E('span', {}, ' · 封禁：' +
                    durationString(runtime.ban_seconds || 604800))
            ]),
            E('p', {}, '31080、58964、20443 不参与蜜罐触发及 Guard 封禁。'),
            table(['来源 IP', '国家', '触发原因', '协议/端口', '首次发现', '到期时间'],
                guardBans),
            runtime.last_error ? E('p', { 'class': 'gw-error' },
                '规则错误：' + runtime.last_error) : E('span'),
            E('p', { 'class': 'gw-muted' },
                'CN 来源访问蜜罐时立即拒绝。旧版规则产生的封禁会保留到原定到期时间。')
        ])),
        panel('海外黑名单（最近 20 条）',
            table(['来源 IP', '地址族', '国家', '封禁到期'], geoBans)),
        (data.errors || []).length ?
            E('p', { 'class': 'gw-error' }, data.errors.join('；')) : E('span'),
        E('div', { 'class': 'gw-footer' }, [
            '更新：' + timeString(data.updated) + ' · ',
            '日志受限速影响，封禁数量以当前集合为准。',
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
