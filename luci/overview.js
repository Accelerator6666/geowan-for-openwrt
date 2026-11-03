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

var getSourceProfile = rpc.declare({
    object: 'geowan', method: 'source_profile', params: [ 'ip', 'period' ]
});

var getAsnProfile = rpc.declare({
    object: 'geowan', method: 'asn_profile', params: [ 'asn', 'period' ]
});

var getCorrelations = rpc.declare({
    object: 'geowan', method: 'correlations', params: [ 'period' ]
});

var getGuardOverview = rpc.declare({
    object: 'geowan', method: 'guard_overview', params: [ 'period', 'public_port' ]
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


function profilePanel() {
    var ipInput = E('input', {
        'type': 'text', 'class': 'cbi-input-text',
        'placeholder': '公网来源 IP，例如 8.8.8.8',
        'autocomplete': 'off', 'spellcheck': 'false'
    });
    var asnInput = E('input', {
        'type': 'number', 'class': 'cbi-input-text',
        'placeholder': 'ASN，例如 15169', 'min': '1', 'max': '4294967295'
    });
    var period = E('select', { 'class': 'cbi-input-select' }, [
        E('option', { 'value': '1h' }, '最近 1 小时'),
        E('option', { 'value': '24h' }, '最近 24 小时'),
        E('option', { 'value': '7d' }, '最近 7 天'),
        E('option', { 'value': '30d' }, '最近 30 天')
    ]);
    period.value = '24h';

    var sourceButton = E('button', {
        'type': 'button', 'class': 'cbi-button cbi-button-action'
    }, '查询来源画像');
    var asnButton = E('button', {
        'type': 'button', 'class': 'cbi-button cbi-button-action'
    }, '查询 ASN 画像');
    var correlationButton = E('button', {
        'type': 'button', 'class': 'cbi-button'
    }, '刷新关联线索');
    var sourceResult = E('div', { 'class': 'gw-profile-result' },
        '输入公网来源 IP，查询本机已采集到的行为样本。');
    var asnResult = E('div', { 'class': 'gw-profile-result' },
        '输入 ASN，查看该网络组织在本机日志样本中的活动分布。');
    var correlationResult = E('div', { 'class': 'gw-profile-result' },
        '查找相近时间命中相同目标服务的多个来源 IP。');
    var state = { sourceBusy: false, asnBusy: false, correlationBusy: false };

    function errorText(data) {
        var labels = {
            invalid_ip: 'IP 地址格式不正确',
            non_global_ip: '只支持公网 IP；私有、保留和本地地址不进行画像',
            invalid_asn: 'ASN 必须是 1 至 4294967295 的整数',
            invalid_period: '统计范围无效',
            database_unavailable: '本地遥测数据库不可用'
        };
        return labels[data.error] || ('查询失败：' + data.error);
    }

    function sourceView(data) {
        if (data.error) {
            dom.content(sourceResult, errorText(data));
            return;
        }
        if (!data.found) {
            dom.content(sourceResult, '该 IP 在所选时间范围内没有日志样本，也没有可用的 GeoIP 缓存或黑名单记录。');
            return;
        }
        var geo = data.geoip || {};
        var location = [geo.country_name, geo.region, geo.city].filter(Boolean).join(' / ');
        var ban = data.ban;
        var score = data.behavior_score || {};
        var scoreText = score.score == null ? '证据不足' :
            score.score + ' / 100 · ' + score.level;
        var summaryRows = [
            ['来源 IP', data.ip],
            ['国家 / 地区 / 城市', location || '未知（GeoIP 缓存未命中）'],
            ['ASN / 网络组织', geo.asn ? 'AS' + geo.asn + ' ' + (geo.asn_org || '') : '未知'],
            ['统计范围', data.period_label],
            ['日志样本', data.samples],
            ['不同目标 IP / 端口 / 协议', data.unique_targets + ' / ' + data.unique_ports + ' / ' + data.unique_protocols],
            ['活跃时间桶', data.active_buckets],
            ['首次 / 最近样本', timeString(data.first_event) + ' / ' + timeString(data.last_event)],
            ['当前黑名单状态', ban ? (ban.active ? '活跃 · 剩余 ' + durationString(ban.remaining_seconds) : '记录已过期') : '未发现当前封禁记录'],
            ['本地行为观察评分', scoreText]
        ];
        var scoreRows = (score.components || []).map(function(item) {
            return [item.label, item.points + ' / ' + item.max];
        });
        var events = (data.events || []).map(function(item) {
            return [timeString(item.ts), item.dst, item.port, item.proto];
        });
        dom.content(sourceResult, [
            table(['字段', '结果'], summaryRows),
            E('h4', {}, '评分构成（不含 GeoIP 国家、城市或 ASN 名称）'),
            table(['观察维度', '得分'], scoreRows),
            E('div', { 'class': 'gw-columns gw-profile-columns' }, [
                panel('目标端口', table(['端口', '样本数'],
                    (data.top_ports || []).map(function(item) { return [item.port, item.samples]; }))),
                panel('目标地址', table(['目标 IP', '样本数'],
                    (data.top_targets || []).map(function(item) { return [item.dst, item.samples]; }))),
                panel('协议分布', table(['协议', '样本数'],
                    (data.top_protocols || []).map(function(item) { return [item.proto, item.samples]; })))
            ]),
            E('h4', {}, '最近日志样本（最多 30 条）'),
            table(['时间', '目标 IP', '目标端口', '协议'], events),
            E('p', { 'class': 'gw-muted' }, data.disclaimer || '')
        ]);
    }

    function asnView(data) {
        if (data.error) {
            dom.content(asnResult, errorText(data));
            return;
        }
        if (!data.found) {
            dom.content(asnResult, '该 ASN 在所选时间范围内没有匹配到 GeoIP 已识别的日志来源。');
            return;
        }
        var metrics = E('div', { 'class': 'gw-analytics-metrics' }, [
            card('来源 IP', data.unique_sources, '按来源地址去重'),
            card('日志样本', data.samples, '受内核日志限速影响'),
            card('目标 IP / 端口', data.unique_targets + ' / ' + data.unique_ports, '本机观测范围'),
            card('当前活跃封禁来源', data.active_banned_sources, '当前快照，不是区间累计')
        ]);
        var clusters = (data.correlations || []).map(function(item) {
            return [
                timeString(item.time), item.dst, item.port, item.proto,
                item.source_count, item.samples,
                (item.sources || []).map(function(source) { return source.ip; }).join(', ')
            ];
        });
        dom.content(asnResult, [
            E('p', {}, 'AS' + data.asn + ' ' + (data.organization || '') + ' · ' + data.period_label),
            metrics,
            E('div', { 'class': 'gw-columns gw-profile-columns' }, [
                panel('样本最多的来源 IP', table(['来源 IP', '国家', '城市', '样本数'],
                    (data.top_sources || []).map(function(item) {
                        return [item.ip, item.country_name || item.country_code,
                            item.city, item.samples];
                    }))),
                panel('目标端口', table(['端口', '样本数'],
                    (data.top_ports || []).map(function(item) { return [item.port, item.samples]; }))),
                panel('目标地址', table(['目标 IP', '样本数'],
                    (data.top_targets || []).map(function(item) { return [item.dst, item.samples]; }))),
                panel('协议分布', table(['协议', '样本数'],
                    (data.top_protocols || []).map(function(item) { return [item.proto, item.samples]; })))
            ]),
            E('h4', {}, '同一 ASN 内的共同观测线索（至少 2 个来源 IP）'),
            table(['时间', '目标 IP', '端口', '协议', '来源 IP 数', '样本数', '来源 IP'],
                clusters),
            E('p', { 'class': 'gw-muted' },
                'ASN 代表网络注册归属，不代表恶意组织。大型云厂商、CDN、VPN 和托管网络可能承载大量不同客户。' +
                (data.disclaimer || ''))
        ]);
    }

    function correlationView(data) {
        if (data.error) {
            dom.content(correlationResult, errorText(data));
            return;
        }

        var clusters = data.clusters || [];
        var rows = clusters.map(function(item) {
            return [
                timeString(item.time), item.dst, item.port, item.proto,
                item.source_count, item.unique_countries || 0,
                item.unique_asns || 0, item.samples
            ];
        });

        var details = clusters.map(function(item) {
            var countryRows = (item.countries || []).map(function(country) {
                return [
                    country.country_name || country.country_code,
                    country.country_code,
                    country.source_count,
                    country.samples
                ];
            });
            var asnRows = (item.asns || []).map(function(asn) {
                return [
                    'AS' + asn.asn,
                    asn.organization,
                    asn.source_count,
                    asn.samples
                ];
            });
            var breakdownWarnings = [];
            if (item.countries_truncated) {
                breakdownWarnings.push('国家 / 地区分布仅显示前 50 项');
            }
            if (item.asns_truncated) {
                breakdownWarnings.push('ASN 分布仅显示前 50 项');
            }
            var sourceRows = (item.sources || []).map(function(source) {
                return [
                    source.ip,
                    source.country_name || source.country_code || '未知',
                    source.asn ? 'AS' + source.asn : '未知',
                    source.asn_org || '',
                    source.samples
                ];
            });
            var heading = timeString(item.time) + ' · ' +
                item.dst + ':' + item.port + '/' + item.proto +
                ' · ' + item.source_count + ' 源 / ' +
                (item.unique_countries || 0) + ' 国家或地区 / ' +
                (item.unique_asns || 0) + ' ASN';

            return E('details', { 'class': 'gw-correlation-detail' }, [
                E('summary', {}, heading),
                table(['指标', '结果'], [
                    ['目标服务', item.dst + ':' + item.port + '/' + item.proto],
                    ['不同来源 IP', item.source_count],
                    ['不同国家 / 地区', item.unique_countries || 0],
                    ['不同 ASN', item.unique_asns || 0],
                    ['国家归属已识别来源', item.country_known_sources || 0],
                    ['ASN 归属已识别来源', item.asn_known_sources || 0],
                    ['GeoIP 完全未识别来源', item.geoip_unresolved_sources || 0],
                    ['日志样本', item.samples],
                    ['固定时间桶', timeString(item.bucket_start || item.time) +
                        ' — ' + timeString(item.bucket_end)]
                ]),
                E('div', { 'class': 'gw-columns gw-profile-columns' }, [
                    panel('国家 / 地区分布（最多 50 项）', table(
                        ['国家 / 地区', '代码', '来源 IP', '样本数'],
                        countryRows
                    )),
                    panel('ASN / 网络组织分布（最多 50 项）', table(
                        ['ASN', '网络组织', '来源 IP', '样本数'],
                        asnRows
                    ))
                ]),
                E('h4', {}, '来源 IP 明细（最多 ' + (item.source_limit || 100) + ' 条）'),
                table(
                    ['来源 IP', '国家 / 地区', 'ASN', '网络组织', '样本数'],
                    sourceRows
                ),
                item.sources_truncated ?
                    E('p', { 'class': 'gw-error' },
                        '来源总数超过单簇返回上限 ' + item.source_limit +
                        '，当前仅显示 ' + item.sources_returned + ' 条。') :
                    E('p', { 'class': 'gw-muted' },
                        '已显示该关联簇的全部 ' + item.sources_returned + ' 个来源 IP。'),
                breakdownWarnings.length ?
                    E('p', { 'class': 'gw-muted' }, breakdownWarnings.join('；')) :
                    E('span')
            ]);
        });

        dom.content(correlationResult, [
            E('p', {}, data.period_label + ' · 至少 ' +
                data.minimum_sources + ' 个不同来源 IP · 固定 UTC 时间桶 ' +
                data.bucket_seconds + ' 秒'),
            table(
                ['时间桶', '目标 IP', '端口', '协议', '来源 IP 数',
                    '国家 / 地区数', 'ASN 数', '样本数'],
                rows
            ),
            E('h4', {}, '关联簇详情（展开查看国家、ASN 和来源 IP 明细）'),
            details,
            E('p', { 'class': 'gw-muted' },
                '国家和 ASN 数量按已识别的不同来源 IP 去重统计。GeoIP 未命中来源仍计入来源 IP 总数。' +
                '共同命中只表示固定时间桶内的网络观测特征，不足以证明来源属于同一攻击者或同一组织。' +
                (data.disclaimer || ''))
        ]);
    }

    sourceButton.addEventListener('click', function() {
        var value = ipInput.value.trim();
        if (!value || state.sourceBusy) return;
        state.sourceBusy = true;
        sourceButton.disabled = true;
        dom.content(sourceResult, '正在生成来源画像……');
        getSourceProfile(value, period.value).then(sourceView).catch(function(error) {
            dom.content(sourceResult, '来源画像 RPC 失败：' + String(error));
        }).finally(function() {
            state.sourceBusy = false;
            sourceButton.disabled = false;
        });
    });
    ipInput.addEventListener('keydown', function(event) {
        if (event.key == 'Enter') sourceButton.click();
    });

    asnButton.addEventListener('click', function() {
        var value = Number(asnInput.value);
        if (!Number.isInteger(value) || value < 1 || value > 4294967295 || state.asnBusy) {
            dom.content(asnResult, '请输入有效 ASN（1 至 4294967295）。');
            return;
        }
        state.asnBusy = true;
        asnButton.disabled = true;
        dom.content(asnResult, '正在生成 ASN 画像……');
        getAsnProfile(value, period.value).then(asnView).catch(function(error) {
            dom.content(asnResult, 'ASN 画像 RPC 失败：' + String(error));
        }).finally(function() {
            state.asnBusy = false;
            asnButton.disabled = false;
        });
    });
    asnInput.addEventListener('keydown', function(event) {
        if (event.key == 'Enter') asnButton.click();
    });

    correlationButton.addEventListener('click', function() {
        if (state.correlationBusy) return;
        state.correlationBusy = true;
        correlationButton.disabled = true;
        dom.content(correlationResult, '正在分析共同观测线索……');
        getCorrelations(period.value).then(correlationView).catch(function(error) {
            dom.content(correlationResult, '关联分析 RPC 失败：' + String(error));
        }).finally(function() {
            state.correlationBusy = false;
            correlationButton.disabled = false;
        });
    });

    var controls = E('div', { 'class': 'gw-profile-controls' }, [
        E('label', {}, ['统计范围', period]),
        E('label', {}, ['来源 IP', ipInput]),
        sourceButton,
        E('label', {}, ['ASN', asnInput]),
        asnButton,
        correlationButton
    ]);
    return panel('攻击来源画像与关联分析（只读）', [
        controls,
        panel('来源 IP 画像', sourceResult),
        panel('ASN / 网络组织画像', asnResult),
        panel('跨来源关联线索', correlationResult),
        E('p', { 'class': 'gw-muted' },
            '本模块只分析已有 SQLite 日志样本和 GeoIP 缓存，不修改 nftables、不封禁或解封 IP、不调用公网逐 IP 查询。')
    ]);
}


function guardPanel() {
    var period = E('select', { 'class': 'gw-guard-period' }, [
        E('option', { 'value': '1h' }, '最近 1 小时'),
        E('option', { 'value': '24h', 'selected': 'selected' }, '最近 24 小时'),
        E('option', { 'value': '7d' }, '最近 7 天'),
        E('option', { 'value': '30d' }, '最近 30 天')
    ]);
    var portFilter = E('select', { 'class': 'gw-guard-port' }, [
        E('option', { 'value': '0', 'selected': 'selected' }, '全部公网端口')
    ]);
    var refreshButton = E('button', {
        'class': 'cbi-button cbi-button-action',
        'type': 'button'
    }, '刷新敏感端口数据');
    var result = E('div', { 'class': 'gw-guard-result' }, '正在读取 Guard 状态……');
    var busy = false;

    function render(data) {
        if (!data || data.error) {
            dom.content(result, E('p', { 'class': 'gw-error' },
                '敏感端口数据暂不可用：' + ((data && data.error) || '未知错误') +
                '。请确认已部署 v0.6.0 并且监控服务已运行。'));
            return;
        }

        var runtime = data.runtime || {};
        var totals = data.totals || {};
        var config = data.config || {};
        var inventory = data.inventory || [];
        var events = data.events || [];
        var alerts = data.alerts || [];
        var selectedPort = String(data.selected_public_port || '0');
        var portOptions = [E('option', { 'value': '0' }, '全部公网端口')];
        var seenPorts = {};
        inventory.forEach(function(item) {
            var key = String(item.public_port);
            if (!item.runtime_active || seenPorts[key]) return;
            seenPorts[key] = true;
            portOptions.push(E('option', { 'value': key },
                key + ' · ' + (item.name || item.category_label || 'DNAT 服务')));
        });
        portOptions = portOptions.slice(0, 65);
        dom.content(portFilter, portOptions);
        portFilter.value = selectedPort;
        if (portFilter.value != selectedPort) {
            portFilter.value = '0';
            selectedPort = '0';
        }
        var stateText = !config.enabled ? '已停用' :
            (runtime.mode == 'observe' && runtime.chain_installed ? '观察模式运行中' :
                (runtime.mode == 'degraded' ? '状态异常' : '等待初始化'));
        var stateClass = config.enabled && runtime.mode == 'observe' &&
            runtime.chain_installed ? 'gw-guard-state-ok' : 'gw-guard-state-warn';

        var inventoryRows = inventory.map(function(item) {
            var family = item.family == 6 ? 'IPv6' : 'IPv4';
            var state = item.conflict ? '映射冲突，跳过采集' :
                (item.runtime_active ? '运行中' : '配置未生效');
            return [
                family, String(item.proto || '').toUpperCase(),
                item.public_port, item.name,
                item.category_label,
                (item.dest_ip || '—') + ':' + (item.dest_port || '—'),
                state
            ];
        });

        var eventRows = events.map(function(item) {
            var country = item.country_name || item.country_code || 'GeoIP 未识别';
            var source = item.src + (item.src_port ? ':' + item.src_port : '');
            var target = (item.dst || '—') + ':' + (item.dest_port || '—');
            return [
                timeString(item.ts), source, country,
                item.public_port, item.service_name,
                target, item.proto
            ];
        });

        var portRows = (data.top_ports || []).map(function(item) {
            return [
                item.public_port,
                String(item.proto || '').toUpperCase(),
                item.unique_sources,
                item.domestic_sources,
                item.foreign_sources,
                item.samples,
                item.services
            ];
        });

        var sourceRows = (data.top_sources || []).map(function(item) {
            return [
                item.src,
                item.country_name || item.country_code || '—',
                item.asn ? ('AS' + item.asn) : '—',
                item.asn_org || '—',
                item.samples
            ];
        });

        var alertRows = alerts.map(function(item) {
            var ports = [];
            try {
                ports = JSON.parse(item.public_ports || '[]');
            } catch (error) {
                ports = [];
            }
            return [
                timeString(item.last_seen), item.src,
                item.country_name || item.country_code || 'GeoIP 未识别',
                item.asn ? ('AS' + item.asn + ' ' + (item.asn_org || '')) : '—',
                ports.join(', ') || '—',
                item.sample_count || 0,
                item.occurrence_count || 1
            ];
        });
        if (!alertRows.length) {
            alertRows = [['—', '—', '—', '—', '暂无告警线索', '—', '—']];
        }

        dom.content(result, [
            E('div', { 'class': 'gw-guard-status ' + stateClass }, [
                E('strong', {}, stateText),
                E('span', {}, ' · WAN 接口：' + (runtime.wan_device || '未识别')),
                E('span', {}, ' · 采集链：' + (runtime.chain_installed ? '已安装' : '未安装'))
            ]),
            E('div', { 'class': 'gw-analytics-metrics gw-guard-metrics' }, [
                card('观察样本', totals.samples || 0, '内核限速日志样本，不是完整连接数'),
                card('不同来源 IP', totals.unique_sources || 0, data.period_label),
                card('国内来源样本', totals.domestic_samples || 0, 'GeoIP 国家代码 CN'),
                card('海外来源样本', totals.foreign_samples || 0, '不含 GeoIP 未识别来源'),
                card('命中服务数', totals.unique_services || 0, '当前统计范围'),
                card('公网端口数', totals.unique_public_ports || 0, '当前统计范围')
            ]),
            E('h4', {}, '多公网端口访问线索（告警模式，仅观察）'),
            table(
                ['最近命中', '来源 IP', 'GeoIP 国家', 'ASN / 网络组织',
                    '访问公网端口', '窗口样本', '告警周期'],
                alertRows
            ),
            E('p', { 'class': 'gw-muted' },
                '默认规则：同一来源在 10 分钟内访问至少 3 个不同公网端口时生成观察告警。'
                + '告警基于限速日志样本，不代表完整连接数或已确认攻击；国家、城市和 ASN 仅作背景信息。'
                + '告警列表是跨端口关联结果，不随上方单端口筛选变化；不会执行封禁或修改防火墙。'),
            E('h4', {}, '公网 DNAT 服务资产（最多 100 项）'),
            table(
                ['地址族', '协议', '公网端口', '服务名称', '分类', '内网目标', '状态'],
                inventoryRows
            ),
            E('p', { 'class': 'gw-muted' },
                '服务清单来自本机 UCI 配置与运行时 nftables DNAT 规则交叉核对。配置未生效或映射冲突的项目不会生成采集规则。'),
            E('h4', {}, '国内来源敏感端口排行'),
            table(
                ['公网端口', '协议', '来源 IP 数', '国内来源', '海外来源', '日志样本', '服务映射数'],
                portRows
            ),
            E('h4', {}, '国内来源 IP 排行'),
            table(
                ['来源 IP', 'GeoIP 国家', 'ASN', '网络组织', '样本数'],
                sourceRows
            ),
            E('h4', {}, '最近敏感端口访问样本（最多 60 条）'),
            table(
                ['时间', '来源 IP:端口', 'GeoIP', '公网端口', '服务', '内网目标', '协议'],
                eventRows
            ),
            runtime.last_error ?
                E('p', { 'class': 'gw-error' }, 'Guard 状态：' + runtime.last_error) :
                E('span'),
            E('p', { 'class': 'gw-muted' }, data.disclaimer || '')
        ]);
    }

    function refresh() {
        if (busy) return;
        busy = true;
        refreshButton.disabled = true;
        dom.content(result, '正在读取敏感端口资产和访问样本……');
        getGuardOverview(period.value, Number(portFilter.value || 0)).then(function(data) {
            render(data);
        }).catch(function(error) {
            dom.content(result, E('p', { 'class': 'gw-error' },
                'Guard RPC 请求失败：' + String(error)));
        }).finally(function() {
            busy = false;
            refreshButton.disabled = false;
        });
    }

    refreshButton.addEventListener('click', refresh);
    period.addEventListener('change', refresh);
    portFilter.addEventListener('change', refresh);
    refresh();

    return panel('公网敏感端口防护（观察模式）', [
        E('div', { 'class': 'gw-guard-controls' }, [
            E('label', {}, ['统计范围', period]),
            E('label', {}, ['公网原始端口', portFilter]),
            refreshButton
        ]),
        result,
        E('p', { 'class': 'gw-muted' },
            '本版本采集所有来源访问当前公网 DNAT 服务的新建尝试，并按本地 GeoIP 区分国内与海外；可按公网原始端口查看来源画像。不会自动封禁，不会修改现有 DNAT 或 GeoWAN 黑名单。')
    ]);
}

function draw(d, lookupNode, blacklistNode, analyticsNode, profileNode, guardNode) {
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
        profileNode || E('span'),
        guardNode || E('span'),
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
        var profile = profilePanel();
        var guard = guardPanel();
        var app = draw(data, lookup, blacklist, analytics, profile, guard);
        var root = E('div', {}, app);
        poll.add(function() {
            return readStatus('/tmp/geowan-console/status.json').then(function(next) {
                var refreshed = draw(dataFromRpc(next), lookup, blacklist, analytics, profile, guard);
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
