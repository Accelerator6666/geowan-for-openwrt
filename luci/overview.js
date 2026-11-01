'use strict';
'require view';
'require rpc';
'require poll';
'require dom';

var readStatus = rpc.declare({
    object: 'file', method: 'read', params: [ 'path' ],
    expect: { data: '' }
});

var lookupIp = rpc.declare({
    object: 'geowan', method: 'lookup', params: [ 'ip' ]
});

var listBans = rpc.declare({
    object: 'geowan', method: 'list_bans',
    params: [ 'page', 'page_size', 'query', 'family', 'country_code',
              'asn', 'port', 'proto', 'sort' ]
});

var getBan = rpc.declare({
    object: 'geowan', method: 'get_ban', params: [ 'ip' ]
});

var getAnalytics = rpc.declare({
    object: 'geowan', method: 'analytics', params: [ 'period' ]
});

function timeString(epoch) {
    return epoch ? new Date(epoch * 1000).toLocaleString() : '—';
}

function durationString(seconds) {
    seconds = Math.max(0, Math.floor(Number(seconds) || 0));
    if (!seconds) return '已过期';
    if (seconds < 60) return seconds + ' 秒';
    var days = Math.floor(seconds / 86400);
    var hours = Math.floor((seconds % 86400) / 3600);
    var minutes = Math.floor((seconds % 3600) / 60);
    if (days) return days + ' 天 ' + hours + ' 小时';
    if (hours) return hours + ' 小时 ' + minutes + ' 分钟';
    return minutes + ' 分钟';
}

function dataFromRpc(data) {
    if (typeof data == 'string') return JSON.parse(data);
    if (data && typeof data.data == 'string') return JSON.parse(data.data);
    throw new Error('未收到有效的状态文件');
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
                return E('td', {}, c == null ? '—' : String(c));
            }));
        }) : E('tr', {}, E('td', { 'colspan': headers.length }, '暂无数据')))
    ]);
}

function panel(title, body) {
    var children = [ E('h3', {}, title) ];
    if (Array.isArray(body))
        children = children.concat(body);
    else if (body != null)
        children.push(body);
    return E('section', { 'class': 'gw-panel' }, children);
}

function lookupPanel() {
    var input = E('input', {
        'type': 'text',
        'class': 'cbi-input-text',
        'placeholder': '输入公网 IPv4 或 IPv6 地址',
        'autocomplete': 'off',
        'spellcheck': 'false'
    });
    var button = E('button', {
        'type': 'button',
        'class': 'cbi-button cbi-button-action'
    }, '查询归属地');
    var result = E('div', { 'class': 'gw-lookup-result' }, '输入 IP 地址后查询本地离线数据库。');

    function runLookup() {
        var value = input.value.trim();
        if (!value) {
            dom.content(result, '请输入 IP 地址。');
            return;
        }
        button.disabled = true;
        dom.content(result, '正在查询……');
        lookupIp(value).then(function(data) {
            button.disabled = false;
            if (data.error) {
                dom.content(result, '查询失败：' + data.error);
                return;
            }
            if (data.lookup_status != 'ok') {
                var labels = {
                    invalid: 'IP 地址格式不正确',
                    non_global: '这是非公网地址，不进行公网归属地定位',
                    unavailable: 'GeoIP 数据库或 MMDB Reader 尚未安装',
                    not_found: '数据库中没有匹配记录'
                };
                dom.content(result, labels[data.lookup_status] || '未能取得归属信息');
                return;
            }
            dom.content(result, table(['字段', '查询结果'], [
                ['IP 地址', data.ip],
                ['国家 / 地区', (data.country_name || '未知') + (data.country_code ? ' (' + data.country_code + ')' : '')],
                ['大洲', data.continent_name || data.continent_code],
                ['省份 / 州', data.region],
                ['城市', data.city],
                ['ASN', data.asn ? 'AS' + data.asn : ''],
                ['网络组织', data.asn_org],
                ['数据源', data.provider + ' · ' + data.database_version]
            ]));
        }).catch(function(error) {
            button.disabled = false;
            dom.content(result, 'RPC 查询失败：' + String(error));
        });
    }

    button.addEventListener('click', runLookup);
    input.addEventListener('keydown', function(event) {
        if (event.key == 'Enter') runLookup();
    });

    return panel('IP 归属地查询（本地离线数据库）',
        E('div', { 'class': 'gw-lookup' }, [input, button, result]));
}

function blacklistPanel() {
    var query = E('input', {
        'type': 'text', 'class': 'cbi-input-text',
        'placeholder': '搜索 IP、国家、城市或网络组织',
        'autocomplete': 'off', 'spellcheck': 'false'
    });
    var family = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '0' }, '全部协议族'),
        E('option', { 'value': '4' }, 'IPv4'),
        E('option', { 'value': '6' }, 'IPv6')
    ]);
    var country = E('input', {
        'type': 'text', 'class': 'cbi-input-text',
        'placeholder': '国家代码，如 US、JP',
        'maxlength': '3', 'autocomplete': 'off'
    });
    var asn = E('input', {
        'type': 'number', 'class': 'cbi-input-text',
        'placeholder': 'ASN，如 15169', 'min': '1'
    });
    var port = E('input', {
        'type': 'number', 'class': 'cbi-input-text',
        'placeholder': '目标端口，如 31080', 'min': '1', 'max': '65535'
    });
    var proto = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '' }, '全部协议'),
        E('option', { 'value': 'TCP' }, 'TCP'),
        E('option', { 'value': 'UDP' }, 'UDP'),
        E('option', { 'value': 'ICMP' }, 'ICMP'),
        E('option', { 'value': 'ICMPV6' }, 'ICMPv6'),
        E('option', { 'value': 'GRE' }, 'GRE'),
        E('option', { 'value': 'ESP' }, 'ESP')
    ]);
    var sort = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': 'last_seen' }, '最近发现优先'),
        E('option', { 'value': 'first_seen' }, '首次发现优先'),
        E('option', { 'value': 'expires_at' }, '即将过期优先'),
        E('option', { 'value': 'ip' }, '按 IP 排序')
    ]);
    var apply = E('button', {
        'type': 'button', 'class': 'cbi-button cbi-button-action'
    }, '查询 / 筛选');
    var clear = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '清空条件');
    var summary = E('div', { 'class': 'gw-list-summary' }, '正在读取活跃黑名单……');
    var list = E('div', { 'class': 'gw-list-table' });
    var detail = E('div', { 'class': 'gw-ban-detail' });
    var first = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '首页');
    var previous = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '上一页');
    var next = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '下一页');
    var last = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '末页');
    var pageLabel = E('span', { 'class': 'gw-page-label' }, '第 1 页');
    var pageSize = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '20' }, '20'),
        E('option', { 'value': '50' }, '50'),
        E('option', { 'value': '100' }, '100')
    ]);
    pageSize.value = '50';
    var state = {
        page: 1, pages: 1, busy: false, pageSize: 50, detailRequest: 0
    };

    function updatePager() {
        first.disabled = state.busy || state.page <= 1;
        previous.disabled = state.busy || state.page <= 1;
        next.disabled = state.busy || state.page >= state.pages;
        last.disabled = state.busy || state.page >= state.pages;
        pageSize.disabled = state.busy;
    }

    var closeDetail = E('button', {
        'type': 'button', 'class': 'cbi-button cbi-button-small'
    }, '关闭详情');
    closeDetail.addEventListener('click', function() {
        state.detailRequest++;
        dom.content(detail, '');
    });

    function detailHeading(ip) {
        return E('div', { 'class': 'gw-detail-heading' }, [
            E('h4', {}, 'IP 详情：' + ip),
            closeDetail
        ]);
    }

    function numberOrZero(value) {
        if (value == null || String(value).trim() === '') return 0;
        var parsed = Number(value);
        return Number.isInteger(parsed) && parsed >= 0 ? parsed : -1;
    }

    function showDetail(ip) {
        var requestId = ++state.detailRequest;
        dom.content(detail, [
            detailHeading(ip),
            E('p', {}, '正在读取 ' + ip + ' 的详情……')
        ]);
        getBan(ip).then(function(data) {
            if (requestId !== state.detailRequest) return;
            if (data.error) {
                dom.content(detail, [
                    detailHeading(ip),
                    E('p', {}, '详情查询失败：' + data.error)
                ]);
                return;
            }
            if (!data.found) {
                dom.content(detail, [
                    detailHeading(ip),
                    E('p', {}, '未找到该 IP 的封禁记录。')
                ]);
                return;
            }
            var item = data.item;
            var location = [item.region, item.city].filter(Boolean).join(' / ');
            var rows = [
                ['IP 地址', item.ip],
                ['协议族', 'IPv' + item.family],
                ['国家 / 地区', (item.country_name || '未知') + (item.country_code ? ' (' + item.country_code + ')' : '')],
                ['大洲', item.continent_name || item.continent_code],
                ['地区 / 城市', location],
                ['ASN', item.asn ? 'AS' + item.asn : ''],
                ['网络组织', item.asn_org],
                ['GeoIP 数据库', (item.provider || '—') + ' · ' + (item.database_version || '—')],
                ['归属查询状态', item.lookup_status],
                ['封禁状态', item.active ? '活跃' : '已过期（等待对账清理）'],
                ['首次发现', timeString(item.first_seen)],
                ['最近发现', timeString(item.last_seen)],
                ['封禁到期', timeString(item.expires_at)],
                ['剩余封禁时间', durationString(item.remaining_seconds)],
                ['日志采样事件数', item.event_count]
            ];
            var events = (item.events || []).map(function(event) {
                return [timeString(event.ts), event.dst, event.port, event.proto];
            });
            dom.content(detail, E('div', {}, [
                detailHeading(item.ip),
                table(['字段', '信息'], rows),
                E('h4', {}, '最近日志样本（最多 30 条）'),
                table(['时间', '目标 IP', '目标端口', '协议'], events),
                E('p', { 'class': 'gw-muted' },
                    '日志样本受内核限速和 30 天保留策略影响，不代表该 IP 的全部连接或全部攻击次数。')
            ]));
        }).catch(function(error) {
            if (requestId !== state.detailRequest) return;
            dom.content(detail, [
                detailHeading(ip),
                E('p', {}, '详情查询失败：' + String(error))
            ]);
        });
    }

    function renderPage(data) {
        if (data.error) {
            dom.content(summary, '查询失败：' + data.error);
            dom.content(list, '');
            updatePager();
            return;
        }

        state.page = data.page || state.page;
        state.pages = Math.max(1, data.pages || 1);
        state.pageSize = data.page_size || state.pageSize;
        pageSize.value = String(state.pageSize);
        dom.content(summary,
            '共 ' + data.total + ' 条活跃封禁记录 · 第 ' + data.page +
            ' / ' + state.pages + ' 页 · 每页 ' + data.page_size + ' 条。' +
            '端口 / 协议筛选基于内核日志样本；剩余封禁时间按本次查询时刻计算。');

        var rows = (data.items || []).map(function(item) {
            var location = [item.region, item.city].filter(Boolean).join(' / ');
            var asnText = item.asn ? 'AS' + item.asn + ' ' + (item.asn_org || '') : '';
            var remaining = Math.max(
                0, Number(item.expires_at || 0) - Math.floor(Date.now() / 1000)
            );
            var ttl = E('span', {
                'class': remaining <= 3600 ? 'gw-ttl-warn' : 'gw-ttl-ok'
            }, durationString(remaining));
            var button = E('button', {
                'type': 'button', 'class': 'cbi-button cbi-button-small'
            }, '详情');
            button.addEventListener('click', function() {
                showDetail(item.ip);
            });
            return E('tr', {}, [
                E('td', {}, item.ip),
                E('td', {}, 'IPv' + item.family),
                E('td', {}, item.country_name || item.country_code || '待识别'),
                E('td', {}, location || '—'),
                E('td', {}, asnText || '—'),
                E('td', {}, timeString(item.first_seen)),
                E('td', {}, timeString(item.last_seen)),
                E('td', {}, timeString(item.last_event)),
                E('td', {}, ttl),
                E('td', {}, String(item.event_count || 0)),
                E('td', {}, button)
            ]);
        });

        dom.content(list, E('table', { 'class': 'table gw-table gw-blacklist-table' }, [
            E('thead', {}, E('tr', {}, [
                'IP 地址', '协议族', '国家', '地区 / 城市', 'ASN / 网络组织',
                '首次发现', '最近发现', '最近日志样本', '剩余封禁', '日志样本', '详情'
            ].map(function(label) { return E('th', {}, label); }))),
            E('tbody', {}, rows.length ? rows :
                E('tr', {}, E('td', { 'colspan': '11' }, '没有符合条件的活跃封禁记录。')))
        ]));

        pageLabel.textContent = '第 ' + data.page + ' / ' + state.pages + ' 页';
        updatePager();
    }

    function loadPage(page) {
        if (state.busy) return;
        var familyValue = numberOrZero(family.value);
        var asnValue = numberOrZero(asn.value);
        var portValue = numberOrZero(port.value);
        var pageSizeValue = numberOrZero(pageSize.value);
        if (familyValue < 0 || asnValue < 0 || portValue < 0 ||
            [20, 50, 100].indexOf(pageSizeValue) < 0) {
            dom.content(summary, '筛选数值或每页数量不正确。');
            return;
        }

        state.pageSize = pageSizeValue;
        state.busy = true;
        apply.disabled = true;
        updatePager();
        dom.content(summary, '正在查询黑名单……');

        listBans(
            page, pageSizeValue, query.value.trim(), familyValue,
            country.value.trim().toUpperCase(), asnValue,
            portValue, proto.value, sort.value
        ).then(function(data) {
            state.busy = false;
            apply.disabled = false;
            renderPage(data);
        }).catch(function(error) {
            state.busy = false;
            apply.disabled = false;
            dom.content(summary, '黑名单查询 RPC 失败：' + String(error));
            updatePager();
        });
    }

    apply.addEventListener('click', function() { loadPage(1); });
    query.addEventListener('keydown', function(event) {
        if (event.key == 'Enter') loadPage(1);
    });
    first.addEventListener('click', function() { loadPage(1); });
    last.addEventListener('click', function() { loadPage(state.pages); });
    pageSize.addEventListener('change', function() { loadPage(1); });
    clear.addEventListener('click', function() {
        query.value = '';
        family.value = '0';
        country.value = '';
        asn.value = '';
        port.value = '';
        proto.value = '';
        sort.value = 'last_seen';
        pageSize.value = '50';
        loadPage(1);
    });
    previous.addEventListener('click', function() {
        if (state.page > 1) loadPage(state.page - 1);
    });
    next.addEventListener('click', function() {
        if (state.page < state.pages) loadPage(state.page + 1);
    });

    var filterGrid = E('div', { 'class': 'gw-filter-grid' }, [
        E('label', {}, ['搜索', query]),
        E('label', {}, ['协议族', family]),
        E('label', {}, ['国家代码', country]),
        E('label', {}, ['ASN', asn]),
        E('label', {}, ['目标端口', port]),
        E('label', {}, ['协议', proto]),
        E('label', {}, ['排序', sort])
    ]);
    var controls = E('div', { 'class': 'gw-filter-actions' }, [
        apply, clear,
        E('span', { 'class': 'gw-filter-hint' },
            '说明：端口与协议条件匹配已采集到的拒绝日志样本。')
    ]);
    var pager = E('div', { 'class': 'gw-pagination' }, [
        first, previous, pageLabel, next, last,
        E('label', { 'class': 'gw-page-size' }, ['每页', pageSize, '条'])
    ]);

    var root = panel('持久化黑名单查询与 IP 详情', [
        filterGrid, controls, summary, list, pager, detail
    ]);
    loadPage(1);
    return root;
}

function analyticsPanel() {
    var period = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '1h' }, '最近 1 小时'),
        E('option', { 'value': '24h' }, '最近 24 小时'),
        E('option', { 'value': '7d' }, '最近 7 天'),
        E('option', { 'value': '30d' }, '最近 30 天')
    ]);
    period.value = '24h';

    var refresh = E('button', {
        'type': 'button', 'class': 'cbi-button cbi-button-action'
    }, '刷新分析');
    var summary = E('div', { 'class': 'gw-list-summary' }, '正在加载趋势分析……');
    var metrics = E('div', { 'class': 'gw-analytics-metrics' });
    var bars = E('div', { 'class': 'gw-bars gw-analytics-bars' });
    var axis = E('div', { 'class': 'gw-chart-axis' });
    var countries = E('div', {});
    var asns = E('div', {});
    var ports = E('div', {});
    var protocols = E('div', {});
    var sources = E('div', {});
    var state = { busy: false };

    function axisLabel(epoch, selectedPeriod) {
        var date = new Date(epoch * 1000);
        return selectedPeriod == '1h' || selectedPeriod == '24h' ?
            date.toLocaleTimeString() : date.toLocaleDateString();
    }

    function render(data) {
        if (data.error) {
            dom.content(summary, '趋势分析查询失败：' + data.error);
            dom.content(metrics, '');
            dom.content(bars, '');
            dom.content(countries, '');
            dom.content(asns, '');
            dom.content(ports, '');
            dom.content(protocols, '');
            dom.content(sources, '');
            return;
        }

        dom.content(summary,
            data.period_label + ' · ' + timeString(data.from_ts) + ' 至 ' +
            timeString(data.to_ts) + ' · GeoIP 数据库 ' + data.database_version);

        dom.content(metrics, [
            card('日志事件样本', data.event_samples || 0, '受内核日志限速影响'),
            card('唯一来源 IP', data.unique_sources || 0, '按来源地址去重'),
            card('当前活跃黑名单', data.active_bans || 0, '当前快照，不是区间累计')
        ]);

        var points = data.trend || [];
        var max = Math.max(1, ...points.map(function(item) {
            return item.count || 0;
        }));
        dom.content(bars, points.map(function(item) {
            return E('div', {
                'class': 'gw-bar',
                'title': timeString(item.time) + '：' + item.count + ' 条日志样本',
                'style': 'height:' + Math.max(2, Math.round((item.count || 0) / max * 100)) + '%'
            });
        }));
        dom.content(axis, [
            E('span', {}, points.length ? axisLabel(points[0].time, data.period) : '—'),
            E('span', {}, points.length ? axisLabel(points[points.length - 1].time, data.period) : '—')
        ]);

        dom.content(countries, table(['国家 / 地区', '代码', '来源 IP', '样本数'],
            (data.top_countries || []).map(function(item) {
                return [item.country, item.code, item.source_ips, item.samples];
            })));
        dom.content(asns, table(['ASN', '网络组织', '来源 IP', '样本数'],
            (data.top_asns || []).map(function(item) {
                return [item.asn ? 'AS' + item.asn : '', item.organization,
                    item.source_ips, item.samples];
            })));
        dom.content(ports, table(['目标端口', '用途', '样本数'],
            (data.top_ports || []).map(function(item) {
                return [item.port, item.service, item.samples];
            })));
        dom.content(protocols, table(['协议', '样本数'],
            (data.top_protocols || []).map(function(item) {
                return [item.proto, item.samples];
            })));
        dom.content(sources, table(['来源 IP', '国家', '城市', 'ASN / 网络组织', '样本数'],
            (data.top_sources || []).map(function(item) {
                return [item.ip, item.country || item.country_code, item.city,
                    item.asn ? 'AS' + item.asn + ' ' + (item.asn_org || '') : '',
                    item.samples];
            })));
    }

    function load() {
        if (state.busy) return;
        state.busy = true;
        refresh.disabled = true;
        dom.content(summary, '正在查询 ' + period.options[period.selectedIndex].text + '……');
        getAnalytics(period.value).then(function(data) {
            render(data);
        }).catch(function(error) {
            dom.content(summary, '趋势分析 RPC 失败：' + String(error));
        }).finally(function() {
            state.busy = false;
            refresh.disabled = false;
        });
    }

    period.addEventListener('change', load);
    refresh.addEventListener('click', load);

    var controls = E('div', { 'class': 'gw-analytics-controls' }, [
        E('label', {}, ['统计范围', period]),
        refresh
    ]);

    var root = panel('攻击趋势与来源分析', [
        controls,
        summary,
        metrics,
        bars,
        axis,
        E('div', { 'class': 'gw-columns gw-analytics-columns' }, [
            panel('来源国家 / 地区（日志样本）', countries),
            panel('来源 ASN / 网络组织（日志样本）', asns),
            panel('目标端口（日志样本）', ports),
            panel('协议分布（日志样本）', protocols)
        ]),
        panel('日志样本最多的来源 IP', sources),
        E('p', { 'class': 'gw-muted' },
            '统计范围仅覆盖已采集到的 GEOWAN 内核日志样本。内核日志限速可能丢弃部分记录；样本数不等于完整连接数或攻击总量。' +
            '本面板只读，不参与防火墙决策；计数器每 5 秒更新，黑名单盘点和日志扫描每 15 秒执行，页面每 5 秒刷新，因此面板可见性通常可能滞后约 0–20 秒，实际受系统调度影响。现有 nftables 规则独立执行匹配。')
    ]);
    load();
    return root;
}

function draw(d, lookupNode, blacklistNode, analyticsNode) {
    var counters = d.counters || {};
    var total = (counters.black4 || 0) + (counters.geo4 || 0) +
                (counters.black6 || 0) + (counters.geo6 || 0);
    var header = E('div', { 'class': 'gw-heading' }, [
        E('div', {}, [
            E('h2', {}, 'GeoWAN 安全防护'),
            E('p', {}, 'OpenWrt firewall4 · WAN 入站观测 · 只读控制台')
        ]),
        E('span', { 'class': 'gw-status ' + (d.status == 'ok' ? 'ok' : 'warn') },
            d.status == 'ok' ? '采集正常' : '数据不完整')
    ]);

    return E('div', { 'class': 'gw-app' }, [
        E('link', { 'rel': 'stylesheet', 'href': L.resource('geowan/geowan.css') }),
        header,
        E('div', { 'class': 'gw-cards' }, [
            card('活跃黑名单记录', d.active_bans || 0, 'IPv4 / IPv6 · 过期自动释放'),
            card('本次规则加载以来丢弃包', total, 'nftables counter，非历史累计'),
            card('过去 24 小时日志样本', d.samples_24h || 0, '受内核日志限速影响'),
            card('监控数据更新', timeString(d.updated), d.collector && d.collector.mode == 'fast' ? '快速监控运行中' : '定时对账模式'),
            card('GeoIP 数据库', d.geoip && d.geoip.enabled ? d.geoip.database_version : '未安装', d.geoip ? ('已识别 ' + d.geoip.resolved_active_bans + ' / ' + d.geoip.active_bans + ' 个活跃 IP') : '离线归属查询'),
            card('IPv4 / IPv6 集合', (d.set_sizes && d.set_sizes['4'] != null ? d.set_sizes['4'] : '?')
                + ' / ' + (d.set_sizes && d.set_sizes['6'] != null ? d.set_sizes['6'] : '?'), '活跃 IP 条目数'),
            card('监控周期', d.collector ? ((d.collector.counter_interval_seconds || '?') + 's / '
                + (d.collector.inventory_interval_seconds || '?') + 's / '
                + (d.collector.log_scan_interval_seconds || '?') + 's') : '未知',
                '计数器 / 黑名单盘点 / 日志扫描'),
            card('最近黑名单盘点', d.collector ? timeString(d.collector.last_inventory) : '未知',
                '面板可见性有采集与刷新延迟')
        ]),
        lookupNode || E('span'),
        analyticsNode || E('span'),
        E('div', { 'class': 'gw-columns' }, [
            panel('海外来源国家排行（活跃封禁 IP）', table(['国家', '国家代码', 'IP 数'],
                (d.top_countries || []).map(function(r) { return [r.country, r.code, r.ips]; }))),
            panel('来源 ASN / 网络组织排行（活跃封禁 IP）', table(['ASN', '网络组织', 'IP 数'],
                (d.top_asns || []).map(function(r) { return [r.asn ? ('AS' + r.asn) : '', r.organization, r.ips]; })))
        ]),
        panel('最近的拒绝记录（日志样本）', table(['时间', '来源 IP', '国家', '城市', '目标 IP', '目标端口', '协议'],
            (d.events || []).slice(0, 40).map(function(r) {
                return [timeString(r.time), r.src, r.country || r.country_code, r.city, r.dst, r.port, r.proto];
            }))),
        blacklistNode || E('span'),
        (d.errors || []).length ? E('p', { 'class': 'gw-error' }, d.errors.join('；')) : E('span'),
        E('div', { 'class': 'gw-footer' }, [
            '更新：' + timeString(d.updated) + ' · ' +
            (d.collector ? ('采集：' + d.collector.mode + ' · 计数器：' +
                d.collector.counter_interval_seconds + ' 秒 · 黑名单盘点：' +
                d.collector.inventory_interval_seconds + ' 秒 · 日志扫描：' +
                d.collector.log_scan_interval_seconds + ' 秒 · ') : ''),
            d.disclaimer || '统计数据仅供防火墙运维使用。',
            d.geoip && d.geoip.enabled ? E('a', { 'href': d.geoip.attribution_url, 'target': '_blank', 'rel': 'noopener noreferrer' }, 'IP Geolocation by DB-IP') : ''
        ])
    ]);
}

return view.extend({
    load: function() {
        return readStatus('/tmp/geowan-console/status.json').then(dataFromRpc);
    },
    render: function(data) {
        var lookup = lookupPanel();
        var blacklist = blacklistPanel();
        var analytics = analyticsPanel();
        var app = draw(data, lookup, blacklist, analytics);
        var root = E('div', {}, app);
        poll.add(function() {
            return readStatus('/tmp/geowan-console/status.json').then(function(next) {
                var refreshed = draw(dataFromRpc(next), lookup, blacklist, analytics);
                dom.content(root, refreshed);
            }).catch(function() {
                /* Keep the last known snapshot visible during an RPC outage. */
            });
        }, 5);
        return root;
    },
    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
