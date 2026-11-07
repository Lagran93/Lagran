<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">WAF 防护</div>
        <div class="page-desc">
          为域名开启 Web 应用防火墙：IP 黑白名单、SQL 注入 / XSS / 路径穿越 / 扫描器检测，以及自定义规则
        </div>
      </div>
      <div class="page-actions">
        <button class="btn btn-default" type="button" :disabled="loading" @click="reload">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
      </div>
    </div>

    <div v-if="!domains.length" class="card">
      <EmptyState
        icon="shield"
        title="还没有可配置的域名"
        text="先在「域名管理」接入域名，再回到这里为它开启 WAF 防护。"
      >
        <NuxtLink to="/domains" class="btn btn-primary btn-sm">去接入域名</NuxtLink>
      </EmptyState>
    </div>

    <template v-else>
      <div class="card waf-toolbar">
        <div class="flex-center gap-12" style="flex-wrap: wrap">
          <span class="field-label" style="margin: 0">防护域名</span>
          <select v-model="domainId" class="select" style="min-width: 240px">
            <option v-for="d in domains" :key="d.id" :value="d.id">{{ d.name }}</option>
          </select>
          <StatusTag :tone="settings.enabled ? 'success' : 'neutral'" dot>
            {{ settings.enabled ? '防护已开启' : '防护未开启' }}
          </StatusTag>
          <StatusTag :tone="settings.mode === 'block' ? 'danger' : 'warning'">
            {{ settings.mode === 'block' ? '拦截模式' : '观察模式' }}
          </StatusTag>
          <span class="spacer" />
          <span class="text-muted" style="font-size: 12px">
            规则变更后边缘节点约 15 秒内同步
          </span>
        </div>
      </div>

      <div class="card">
        <div class="waf-tabs">
          <button
            v-for="t in tabs"
            :key="t.value"
            type="button"
            class="waf-tab"
            :class="{ active: tab === t.value }"
            @click="switchTab(t.value)"
          >
            {{ t.label }}
            <span v-if="t.count !== undefined" class="tab-count">{{ t.count }}</span>
          </button>
        </div>

        <!-- 数据概览 -->
        <div v-if="tab === 'overview'" class="card-body">
          <div class="stat-grid">
            <StatCard label="事件总数" :value="stats.total" icon="shield" />
            <StatCard label="拦截" :value="actionCount('block')" tone="red" icon="alert" />
            <StatCard label="质询" :value="actionCount('challenge')" tone="orange" icon="zap" />
            <StatCard
              label="观察 / 记录"
              :value="actionCount('monitor') + actionCount('log')"
              tone="green"
              icon="activity"
            />
          </div>

          <div class="section-label">按天趋势（最近 {{ stats.days }} 天）</div>
          <div v-if="stats.by_day.length" class="bar-chart">
            <div
              v-for="d in stats.by_day"
              :key="d.key"
              class="bar-col"
              :title="`${d.key}: ${d.count}`"
            >
              <div class="bar" :style="{ height: barHeight(d.count) }" />
              <span class="bar-label">{{ d.key.slice(5) }}</span>
            </div>
          </div>
          <div v-else class="text-muted" style="font-size: 13px; padding: 12px 0">
            最近 {{ stats.days }} 天暂无 WAF 事件。
          </div>

          <div class="waf-stat-grid">
            <div class="stat-list">
              <div class="stat-list-title">按类型</div>
              <div v-for="c in stats.by_category" :key="c.key" class="stat-list-row">
                <span>{{ categoryLabel(c.key) }}</span>
                <b>{{ c.count }}</b>
              </div>
              <div v-if="!stats.by_category.length" class="stat-empty">暂无</div>
            </div>
            <div class="stat-list">
              <div class="stat-list-title">Top 客户端 IP</div>
              <div v-for="c in stats.top_ips" :key="c.key" class="stat-list-row">
                <span class="mono">{{ c.key }}</span>
                <b>{{ c.count }}</b>
              </div>
              <div v-if="!stats.top_ips.length" class="stat-empty">暂无</div>
            </div>
            <div class="stat-list">
              <div class="stat-list-title">Top 命中规则</div>
              <div v-for="c in stats.top_rules" :key="c.key" class="stat-list-row">
                <span>{{ c.key }}</span>
                <b>{{ c.count }}</b>
              </div>
              <div v-if="!stats.top_rules.length" class="stat-empty">暂无</div>
            </div>
            <div class="stat-list">
              <div class="stat-list-title">Top 路径</div>
              <div v-for="c in stats.top_paths" :key="c.key" class="stat-list-row">
                <span class="mono truncate" :title="c.key">{{ c.key }}</span>
                <b>{{ c.count }}</b>
              </div>
              <div v-if="!stats.top_paths.length" class="stat-empty">暂无</div>
            </div>
          </div>
        </div>

        <!-- 防护设置 -->
        <div v-else-if="tab === 'settings'" class="card-body">
          <div class="alert" :class="settings.mode === 'block' ? 'alert-warning' : 'alert-info'">
            <AppIcon name="shield" :size="16" class="icon" />
            <span v-if="settings.mode === 'block'">
              拦截模式会直接拒绝命中规则的请求（403 页面）。上线初期建议先用观察模式确认没有误报。
            </span>
            <span v-else>
              观察模式只记录事件、不拦截请求。确认规则准确后，再切换为拦截模式。
            </span>
          </div>

          <div class="setting-row">
            <div>
              <div class="setting-title">开启 WAF 防护</div>
              <div class="setting-desc">关闭后该域名的 IP 名单与规则全部不生效</div>
            </div>
            <label class="switch" :class="{ on: settings.enabled }">
              <span class="switch-track" />
              <input v-model="settings.enabled" type="checkbox" style="display: none" />
            </label>
          </div>

          <div class="setting-row">
            <div>
              <div class="setting-title">防护模式</div>
              <div class="setting-desc">观察模式用于灰度验证规则，拦截模式用于正式防护</div>
            </div>
            <div class="segmented">
              <button
                type="button"
                :class="{ active: settings.mode === 'monitor' }"
                @click="settings.mode = 'monitor'"
              >
                观察
              </button>
              <button
                type="button"
                :class="{ active: settings.mode === 'block' }"
                @click="settings.mode = 'block'"
              >
                拦截
              </button>
            </div>
          </div>

          <div class="section-label">安全级别</div>
          <div class="segmented level-seg">
            <button
              v-for="l in securityLevels"
              :key="l.value"
              type="button"
              :class="{ active: settings.security_level === l.value }"
              @click="settings.security_level = l.value"
            >
              {{ l.label }}
            </button>
          </div>
          <p class="text-muted" style="font-size: 12px; margin-top: 8px">
            {{ levelHint }}
          </p>

          <div class="section-label">托管规则集</div>
          <div class="ruleset-grid">
            <label
              v-for="rs in rulesets"
              :key="rs.id"
              class="ruleset-card"
              :class="{ on: settings.managed_rulesets.includes(rs.id) }"
            >
              <input
                type="checkbox"
                :checked="settings.managed_rulesets.includes(rs.id)"
                @change="toggleRuleset(rs.id)"
              />
              <span class="ruleset-body">
                <span class="ruleset-head">
                  <strong>{{ rs.name }}</strong>
                  <span class="ruleset-version">{{ rs.version }}</span>
                  <span v-if="rs.recommended" class="ruleset-badge">推荐</span>
                </span>
                <small>{{ rs.description }}</small>
                <span class="ruleset-categories">
                  <span v-for="(label, i) in rs.category_labels" :key="rs.categories[i]" class="ruleset-chip">
                    {{ label }}
                  </span>
                </span>
              </span>
              <AppIcon :name="settings.managed_rulesets.includes(rs.id) ? 'check' : 'plus'" :size="15" />
            </label>
            <div v-if="!rulesets.length" class="text-muted" style="font-size: 13px">
              正在加载托管规则集…
            </div>
          </div>
          <p class="text-muted" style="font-size: 12px; margin-top: 8px">
            规则集是增量启用：选中后会启用其覆盖的签名类别，不会关闭下方单独开启的规则。规则集版本由控制面统一维护。
          </p>

          <div class="section-label">规则包版本与灰度</div>
          <div class="form-grid">
            <div class="field">
              <label class="field-label">规则包版本</label>
              <select v-model="settings.waf_rulepack_version" class="select">
                <option value="">跟随 active 版本</option>
                <option v-for="p in rulepackVersions" :key="p.version" :value="p.version">
                  {{ p.version }}（{{ p.slot }}）
                </option>
              </select>
              <span class="field-hint">留空跟随控制面 active；固定版本可用于单域名验证/回滚。</span>
            </div>
            <div class="field">
              <label class="field-label">灰度比例</label>
              <input
                v-model.number="settings.waf_gray_percent"
                class="input"
                type="number"
                min="0"
                max="100"
              />
              <span class="field-hint">0 = 全量 active；1~99 按域名稳定哈希切分到 active/previous。</span>
            </div>
          </div>

          <div v-if="auth.isAdmin" class="rulepack-admin">
            <div class="flex-between">
              <span class="text-muted" style="font-size: 12px">
                规则包由 Control 签名，Edge 验签后缓存到本地。回滚只切换 active/previous。
                发布前应先在 Control 中更新内置 catalog；catalog 无变化时发布会返回 409。
              </span>
              <button class="btn btn-default btn-sm" type="button" :disabled="rulepackBusy" @click="publishRulepack">
                发布新版本
              </button>
            </div>
            <div v-if="rulepackVersions.length" class="rulepack-versions">
              <div
                v-for="p in rulepackVersions"
                :key="p.version"
                class="rulepack-version-row"
                :class="`slot-${p.slot}`"
              >
                <div class="version-main">
                  <div class="version-title">
                    <span class="mono version-name">{{ p.version }}</span>
                    <span class="slot-badge" :class="`slot-badge-${p.slot}`">
                      <span class="slot-dot" />
                      {{ slotLabel(p.slot) }}
                    </span>
                  </div>
                  <div class="version-meta">
                    <span>创建 {{ formatRulepackTime(p.created_at) }}</span>
                    <span class="meta-sep">·</span>
                    <span class="mono" :title="p.signature">签名 {{ p.signature.slice(0, 10) }}</span>
                  </div>
                </div>

                <div class="version-actions">
                  <span v-if="p.slot === 'active'" class="current-label">
                    <AppIcon name="check" :size="13" />
                    当前生效
                  </span>
                  <template v-else>
                    <button
                      class="btn btn-default btn-sm version-action"
                      type="button"
                      :disabled="rulepackBusy"
                      @click="rollbackRulepack(p.version)"
                    >
                      设为 active
                    </button>
                    <button
                      v-if="p.slot === 'previous'"
                      class="btn btn-text btn-sm version-action"
                      type="button"
                      :disabled="rulepackBusy"
                      @click="retireRulepack(p.version)"
                    >
                      转为 retired
                    </button>
                    <button
                      v-if="p.slot === 'retired'"
                      class="btn btn-text btn-sm danger version-action"
                      type="button"
                      :disabled="rulepackBusy"
                      @click="deleteRulepack(p.version)"
                    >
                      删除
                    </button>
                  </template>
                </div>
              </div>
            </div>
          </div>

          <div class="section-label">单条托管规则</div>
          <div class="managed-grid">
            <label
              v-for="m in managedRules"
              :key="m.key"
              class="managed-item"
              :class="{ on: settings[m.key] }"
            >
              <input v-model="settings[m.key]" type="checkbox" />
              <span class="managed-info">
                <strong>{{ m.label }}</strong>
                <small>{{ m.desc }}</small>
              </span>
              <AppIcon :name="settings[m.key] ? 'check' : 'plus'" :size="15" />
            </label>
          </div>

          <div class="section-label">浏览器质询</div>
          <div class="form-grid">
            <div class="field">
              <label class="field-label">质询难度（前导 0 的十六进制位数）</label>
              <input
                v-model.number="settings.challenge_difficulty"
                class="input"
                type="number"
                min="1"
                max="6"
              />
              <span class="field-hint">1 最轻、6 最重，默认 4（约 6.5 万次哈希）。</span>
            </div>
            <div class="field">
              <label class="field-label">免质询有效期（秒）</label>
              <input
                v-model.number="settings.challenge_ttl_secs"
                class="input"
                type="number"
                min="60"
                max="86400"
              />
              <span class="field-hint">通过后签发 HttpOnly Cookie，默认 1800 秒。</span>
            </div>
          </div>
          <p class="text-muted" style="font-size: 12px; margin-top: 8px">
            规则动作选择「质询」时生效；仅对 GET/HEAD 且 Accept 包含 text/html 的文档导航返回质询页。
            API / XHR / POST 等非文档请求会跳过质询直接放行，如需限制请使用 block 规则或限流。
          </p>

          <div class="flex-between mt-24">
            <span class="text-muted" style="font-size: 12px">
              托管规则基于常见攻击特征匹配 URL、查询串、UA 与 Referer，不检查请求体。
            </span>
            <button class="btn btn-primary" type="button" :disabled="saving" @click="saveSettings">
              {{ saving ? '保存中…' : '保存设置' }}
            </button>
          </div>
        </div>

        <!-- 自定义规则 -->
        <div v-else-if="tab === 'rules'" class="card-body tight">
          <div class="filter-bar">
            <span class="text-muted" style="font-size: 13px">
              按优先级从高到低匹配，命中即停止；支持拦截、放行、仅记录三种动作
            </span>
            <span class="spacer" />
            <button class="btn btn-primary btn-sm" type="button" @click="openRuleModal()">
              <AppIcon name="plus" :size="14" />
              新建规则
            </button>
          </div>

          <div v-if="rules.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>规则名称</th>
                  <th>匹配条件</th>
                  <th>动作</th>
                  <th>优先级</th>
                  <th>状态</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="r in pagedRules" :key="r.id">
                  <td class="cell-main">{{ r.name }}</td>
                  <td>
                    <span v-if="r.expr" class="mono dsl-cell" :title="r.expr">
                      <span class="dsl-badge">DSL</span>{{ r.expr }}
                    </span>
                    <span v-else class="mono">{{ fieldLabel(r.field) }} {{ opLabel(r.operator) }} {{ r.value }}</span>
                  </td>
                  <td>
                    <StatusTag :tone="actionTone(r.action)">{{ actionLabel(r.action) }}</StatusTag>
                  </td>
                  <td class="num">{{ r.priority }}</td>
                  <td>
                    <StatusTag :tone="r.enabled ? 'success' : 'neutral'" dot>
                      {{ r.enabled ? '启用' : '停用' }}
                    </StatusTag>
                  </td>
                  <td class="text-right">
                    <div class="ops" style="justify-content: flex-end">
                      <button class="btn btn-text btn-sm" type="button" @click="toggleRule(r)">
                        {{ r.enabled ? '停用' : '启用' }}
                      </button>
                      <button class="btn btn-text btn-sm" type="button" @click="openRuleModal(r)">
                        编辑
                      </button>
                      <button class="btn btn-text btn-sm danger" type="button" @click="removeRule(r)">
                        删除
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="rules.length > rulePageSize" class="table-footer">
            <AppPagination v-model:page="rulePage" :total="rules.length" :page-size="rulePageSize" />
          </div>
          <EmptyState
            v-if="!rules.length"
            icon="rules"
            title="还没有自定义规则"
            text="例如：路径前缀 /admin 且来源不属于办公网时拦截，或对 /api/ 只记录日志。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openRuleModal()">
              新建规则
            </button>
          </EmptyState>
        </div>

        <!-- IP 黑白名单 -->
        <div v-else-if="tab === 'ips'" class="card-body tight">
          <div class="filter-bar">
            <span class="text-muted" style="font-size: 13px">
              白名单优先于所有规则；黑名单命中后直接拦截。支持 IPv4/IPv6 与 CIDR
            </span>
            <span class="spacer" />
            <button class="btn btn-primary btn-sm" type="button" @click="openIpModal('deny')">
              <AppIcon name="plus" :size="14" />
              添加 IP / 网段
            </button>
          </div>

          <div v-if="ips.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>类型</th>
                  <th>IP / 网段</th>
                  <th>备注</th>
                  <th>添加时间</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="ip in pagedIps" :key="ip.id">
                  <td>
                    <StatusTag :tone="ip.kind === 'allow' ? 'success' : 'danger'">
                      {{ ip.kind === 'allow' ? '白名单' : '黑名单' }}
                    </StatusTag>
                  </td>
                  <td class="mono">{{ ip.ip }}</td>
                  <td class="text-2">{{ ip.note || '—' }}</td>
                  <td class="text-muted">{{ formatDateTime(ip.created_at) }}</td>
                  <td class="text-right">
                    <button class="btn btn-text btn-sm danger" type="button" @click="removeIp(ip)">
                      删除
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-if="ips.length > ipPageSize" class="table-footer">
            <AppPagination v-model:page="ipPage" :total="ips.length" :page-size="ipPageSize" />
          </div>
          <EmptyState
            v-if="!ips.length"
            icon="shield"
            title="还没有 IP 名单"
            text="把攻击来源加入黑名单，或把办公网、监控探针加入白名单以跳过所有 WAF 检查。"
          >
            <button class="btn btn-primary btn-sm" type="button" @click="openIpModal('deny')">
              添加第一条
            </button>
          </EmptyState>
        </div>

        <!-- 跨节点共享封禁 -->
        <div v-else-if="tab === 'bans'" class="card-body tight">
          <div class="filter-bar">
            <select v-model="banStatusFilter" class="select">
              <option value="">全部状态</option>
              <option value="active">生效中</option>
              <option value="expired">已过期</option>
              <option value="revoked">已解封</option>
            </select>
            <span class="text-muted" style="font-size: 13px">
              当前域名 {{ currentDomainName || '—' }}；当前封禁会同步到所有边缘，过期与已解封记录保留用于审计
            </span>
            <span class="spacer" />
            <button class="btn btn-default btn-sm" type="button" :disabled="bansLoading" @click="loadBans">
              <AppIcon name="refresh" :size="14" />
              刷新
            </button>
            <button
              class="btn btn-primary btn-sm"
              type="button"
              @click="openBanModal"
            >
              <AppIcon name="plus" :size="14" />
              添加封禁
            </button>
            <span class="text-muted" style="font-size: 13px">{{ filteredBans.length }} 条记录</span>
          </div>

          <div v-if="ccStats" class="cc-stat-row">
            <span class="cc-stat"><b>{{ ccStats.active_bans }}</b> 活动封禁</span>
            <span class="cc-stat"><b>{{ ccStats.limited_24h }}</b> 24h 限流</span>
            <span class="cc-stat"><b>{{ ccStats.challenged_24h }}</b> 24h 挑战</span>
            <span class="cc-stat"><b>{{ ccStats.banned_24h }}</b> 24h 封禁</span>
          </div>

          <div v-if="bansError" class="alert alert-warning" style="margin: 12px 16px">
            <AppIcon name="alert" :size="16" class="icon" />
            <span>{{ bansError }}</span>
          </div>

          <div v-if="!bansError && filteredBans.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>状态</th>
                  <th>域名</th>
                  <th>客户端 IP</th>
                  <th>原因</th>
                  <th>来源节点</th>
                  <th>创建时间</th>
                  <th>到期 / 解封</th>
                  <th class="text-right">操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="b in filteredBans" :key="`${b.domain}|${b.ip}`">
                  <td>
                    <StatusTag :tone="banTone(b.status)" dot>{{ banStatusLabel(b.status) }}</StatusTag>
                  </td>
                  <td class="cell-main">{{ b.domain }}</td>
                  <td class="mono">{{ b.ip }}</td>
                  <td class="text-2">{{ b.reason || 'cc-auto-ban' }}</td>
                  <td class="text-2">{{ b.source || '—' }}</td>
                  <td>
                    <div>{{ formatDateTime(b.created_at) }}</div>
                  </td>
                  <td>
                    <template v-if="b.status === 'active'">
                      <div>{{ formatDateTime(b.expires_at) }}</div>
                      <div class="cell-sub">剩余 {{ remainingLabel(b.remaining_secs) }}</div>
                    </template>
                    <template v-else-if="b.status === 'revoked'">
                      <div>{{ formatDateTime(b.revoked_at) }}</div>
                      <div class="cell-sub">由 {{ b.revoked_by || '管理员' }} 解封</div>
                    </template>
                    <template v-else>
                      <div>{{ formatDateTime(b.expires_at) }}</div>
                      <div class="cell-sub">已过期</div>
                    </template>
                  </td>
                  <td class="text-right">
                    <button
                      v-if="b.status === 'active'"
                      class="btn btn-text btn-sm danger"
                      type="button"
                      @click="unbanIp(b)"
                    >
                      解封
                    </button>
                    <span v-else class="text-muted" style="font-size: 12px">—</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else-if="bansLoading" class="card-body">
            <div class="skeleton" style="height: 32px; width: 100%" />
          </div>
          <EmptyState
            v-else-if="!bansError"
            icon="shield"
            :title="bans.length ? '没有匹配的封禁记录' : '暂无共享封禁'"
            :text="
              bans.length
                ? '调整状态筛选条件后再试。'
                : '当前防护域名暂无封禁记录；已过期和已解封记录也会保留。'
            "
          />
        </div>

        <!-- 事件日志 -->
        <div v-else class="card-body tight">
          <div class="filter-bar">
            <select v-model="eventAction" class="select">
              <option value="">全部动作</option>
              <option value="block">拦截</option>
              <option value="challenge">质询</option>
              <option value="monitor">观察</option>
              <option value="log">仅记录</option>
            </select>
            <select v-model.number="eventLimit" class="select">
              <option :value="50">最近 50 条</option>
              <option :value="100">最近 100 条</option>
              <option :value="200">最近 200 条</option>
            </select>
            <button class="btn btn-default" type="button" :disabled="eventsLoading" @click="loadEvents">
              查询
            </button>
            <span class="spacer" />
            <span class="text-muted" style="font-size: 13px">{{ filteredEvents.length }} 条事件</span>
          </div>

          <div v-if="filteredEvents.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>时间</th>
                  <th>动作</th>
                  <th>类型</th>
                  <th>规则</th>
                  <th>客户端 IP</th>
                  <th>方法</th>
                  <th style="min-width: 200px">路径</th>
                  <th>节点</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="e in pagedEvents" :key="e.id">
                  <td class="text-muted nowrap">{{ formatDateTime(e.ts) }}</td>
                  <td>
                    <StatusTag :tone="eventTone(e.action)">{{ eventLabel(e.action) }}</StatusTag>
                  </td>
                  <td>{{ categoryLabel(e.category) }}</td>
                  <td class="text-2">{{ e.rule_name || '—' }}</td>
                  <td class="mono">{{ e.client_ip }}</td>
                  <td class="mono">{{ e.method }}</td>
                  <td><div class="mono path-cell" :title="e.path">{{ e.path }}</div></td>
                  <td class="text-2">{{ e.node_id }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else-if="eventsLoading" class="card-body">
            <div class="skeleton" style="height: 32px; width: 100%" />
          </div>
          <EmptyState
            v-else
            icon="activity"
            title="暂无 WAF 事件"
            text="命中规则的请求会在这里展示；观察模式下只记录不拦截。"
          />
          <div v-if="filteredEvents.length > eventPageSize" class="table-footer">
            <AppPagination v-model:page="eventPage" :total="filteredEvents.length" :page-size="eventPageSize" />
          </div>
        </div>
      </div>
    </template>

    <BaseModal
      v-model="ruleModalOpen"
      :title="editingRule ? '编辑 WAF 规则' : '新建 WAF 规则'"
      confirm-text="保存"
      :loading="saving"
      @confirm="saveRule"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">规则名称 <span class="req">*</span></label>
          <input v-model="ruleForm.name" class="input" placeholder="例如：拦截后台探测" />
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">匹配字段</label>
            <select v-model="ruleForm.field" class="select" :disabled="!!ruleForm.expr.trim()">
              <option value="path">路径 Path</option>
              <option value="query">查询串 Query</option>
              <option value="user_agent">User-Agent</option>
              <option value="referer">Referer</option>
              <option value="method">请求方法</option>
              <option value="ip">客户端 IP</option>
              <option value="header">请求头（自定义）</option>
            </select>
          </div>
          <div v-if="ruleForm.field === 'header'" class="field">
            <label class="field-label">请求头名称 <span class="req">*</span></label>
            <input v-model="ruleForm.header_name" class="input" placeholder="例如 x-api-key" :disabled="!!ruleForm.expr.trim()" />
          </div>
          <div class="field">
            <label class="field-label">匹配方式</label>
            <select v-model="ruleForm.operator" class="select" :disabled="!!ruleForm.expr.trim()">
              <option value="contains">包含</option>
              <option value="equals">等于</option>
              <option value="prefix">前缀</option>
              <option value="suffix">后缀</option>
            </select>
          </div>
          <div class="field span-2">
            <label class="field-label">匹配内容 <span v-if="!ruleForm.expr.trim()" class="req">*</span></label>
            <input v-model="ruleForm.value" class="input" placeholder="例如 /admin 或 sqlmap" :disabled="!!ruleForm.expr.trim()" />
          </div>
          <div class="field">
            <label class="field-label">命中动作</label>
            <select v-model="ruleForm.action" class="select">
              <option value="block">拦截</option>
              <option value="challenge">质询（JS 验证）</option>
              <option value="allow">放行</option>
              <option value="log">仅记录</option>
            </select>
          </div>
          <div class="field">
            <label class="field-label">优先级</label>
            <input v-model.number="ruleForm.priority" class="input" type="number" />
          </div>
        </div>
        <div class="field">
          <label class="field-label">高级条件 DSL（可选）</label>
          <div class="dsl-editor">
            <textarea
              ref="dslTextarea"
              v-model="ruleForm.expr"
              class="textarea mono"
              rows="4"
              placeholder='例如：path prefix "/admin" AND ip in "10.0.0.0/8"'
              @input="updateDslSuggestions"
              @focus="updateDslSuggestions"
              @click="updateDslSuggestions"
              @keydown="onDslKeydown"
              @blur="closeDslSuggestionsSoon"
            />
            <div v-if="dslSuggestOpen && dslSuggestions.length" class="dsl-suggest">
              <button
                v-for="(item, i) in dslSuggestions"
                :key="item.label"
                type="button"
                class="dsl-suggest-item"
                :class="{ active: i === dslSuggestIndex }"
                @mousedown.prevent="applyDslSuggestion(item)"
              >
                <span class="dsl-suggest-label mono">{{ item.label }}</span>
                <span class="dsl-suggest-detail">{{ item.detail }}</span>
              </button>
              <div class="dsl-suggest-foot">↑↓ 选择 · Enter/Tab 补全 · Esc 关闭</div>
            </div>
          </div>
          <span class="field-hint">
            DSL 非空时忽略上面的单条件。支持 path/query/user_agent/referer/method/ip/header:名称、
            contains/equals/prefix/suffix、ip in "CIDR"、AND/OR/NOT 和括号；不允许正则。
          </span>
        </div>
        <label class="check">
          <input v-model="ruleForm.enabled" type="checkbox" />
          启用这条规则
        </label>
        <p v-if="ruleError" class="text-danger" style="font-size: 13px">{{ ruleError }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="ipModalOpen"
      title="添加 IP / 网段"
      confirm-text="添加"
      :loading="saving"
      @confirm="saveIp"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">名单类型</label>
          <div class="segmented">
            <button type="button" :class="{ active: ipForm.kind === 'deny' }" @click="ipForm.kind = 'deny'">
              黑名单
            </button>
            <button type="button" :class="{ active: ipForm.kind === 'allow' }" @click="ipForm.kind = 'allow'">
              白名单
            </button>
          </div>
        </div>
        <div class="field">
          <label class="field-label">IP 或 CIDR <span class="req">*</span></label>
          <input v-model="ipForm.ip" class="input" placeholder="203.0.113.10 或 10.0.0.0/8" />
        </div>
        <div class="field">
          <label class="field-label">备注</label>
          <input v-model="ipForm.note" class="input" placeholder="例如：攻击来源 / 办公网出口" />
        </div>
        <p v-if="ipError" class="text-danger" style="font-size: 13px">{{ ipError }}</p>
      </div>
    </BaseModal>

    <BaseModal
      v-model="banModalOpen"
      title="添加共享封禁"
      confirm-text="封禁"
      :loading="saving"
      @confirm="saveBan"
    >
      <div class="form-col">
        <div class="field">
          <label class="field-label">域名</label>
          <div class="input" style="display: flex; align-items: center; background: var(--bg)">
            {{ currentDomainName || '请先选择防护域名' }}
          </div>
        </div>
        <div class="field">
          <label class="field-label">IP 或 CIDR <span class="req">*</span></label>
          <input v-model="banForm.ip" class="input" placeholder="203.0.113.10 或 203.0.113.0/24" />
          <span class="field-hint">支持 IPv4/IPv6 单 IP 与 CIDR；边缘按域名 + 网段匹配。</span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label class="field-label">封禁时长（秒）</label>
            <input v-model.number="banForm.seconds" class="input" type="number" min="1" max="86400" />
          </div>
          <div class="field">
            <label class="field-label">原因</label>
            <input v-model="banForm.reason" class="input" placeholder="例如：持续 CC 攻击" />
          </div>
        </div>
        <p v-if="banError" class="text-danger" style="font-size: 13px">{{ banError }}</p>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { friendlyErrorMessage } from '~/utils/friendlyError'

const api = useApi()
const toast = useToast()
const { ask } = useConfirm()
const auth = useAuthStore()

type Tab = 'overview' | 'settings' | 'rules' | 'ips' | 'bans' | 'events'

const domains = ref<any[]>([])
const domainId = ref('')
const tab = ref<Tab>('overview')
const loading = ref(false)
const saving = ref(false)

const stats = ref<any>({
  days: 7,
  total: 0,
  by_action: [],
  by_category: [],
  by_day: [],
  top_ips: [],
  top_rules: [],
  top_paths: [],
})
const statsLoading = ref(false)

const securityLevels = [
  { value: 'off', label: '关闭' },
  { value: 'low', label: '低' },
  { value: 'medium', label: '中' },
  { value: 'high', label: '高' },
  { value: 'under_attack', label: '攻击中' },
]

const levelHint = computed(() => {
  const hints: Record<string, string> = {
    off: '只执行 IP 名单与显式规则，不按安全级别额外质询。',
    low: '对空 User-Agent 的 GET/HEAD 请求发起质询。',
    medium: '在低级别基础上，对扫描器 UA 与空 UA 发起质询。',
    high: '对所有文档类 GET/HEAD（HTML 导航）发起质询，静态资源除外。',
    under_attack: '对所有 GET/HEAD 发起质询，静态资源除外；适合正在被攻击时临时开启。',
  }
  return hints[settings.value.security_level] || hints.off
})

const settings = ref<any>({
  enabled: false,
  mode: 'block',
  sqli: true,
  xss: true,
  traversal: true,
  scanners: true,
  rce: true,
  ssrf: true,
  xxe: true,
  log4shell: true,
  crlf: true,
  ssti: true,
  nosql: true,
  ldap: true,
  java: true,
  webshell: true,
  protocol: true,
  security_level: 'off',
  challenge_difficulty: 4,
  challenge_ttl_secs: 1800,
  managed_rulesets: [] as string[],
  waf_rulepack_version: '',
  waf_gray_percent: 0,
})

const rules = ref<any[]>([])
const rulesets = ref<any[]>([])
const rulepackVersions = ref<any[]>([])
const rulepackBusy = ref(false)
const ips = ref<any[]>([])
const rulePage = ref(1)
const ipPage = ref(1)
const rulePageSize = 10
const ipPageSize = 10
const pagedRules = computed(() => {
  const start = (rulePage.value - 1) * rulePageSize
  return rules.value.slice(start, start + rulePageSize)
})
const pagedIps = computed(() => {
  const start = (ipPage.value - 1) * ipPageSize
  return ips.value.slice(start, start + ipPageSize)
})
watch(
  () => rules.value.length,
  (total) => {
    rulePage.value = Math.min(rulePage.value, Math.max(1, Math.ceil(total / rulePageSize)))
  },
)
watch(
  () => ips.value.length,
  (total) => {
    ipPage.value = Math.min(ipPage.value, Math.max(1, Math.ceil(total / ipPageSize)))
  },
)
const events = ref<any[]>([])
const eventsLoading = ref(false)
const eventAction = ref('')
const eventLimit = ref(100)

const bans = ref<any[]>([])
const bansLoading = ref(false)
const bansError = ref('')
const banStatusFilter = ref('')
const currentDomainName = computed(
  () => domains.value.find((d) => d.id === domainId.value)?.name || ''
)
const filteredBans = computed(() => {
  if (!banStatusFilter.value) return bans.value
  return bans.value.filter((b) => b.status === banStatusFilter.value)
})
const ccStats = ref<any>(null)

const ruleModalOpen = ref(false)
const editingRule = ref<any>(null)
const ruleError = ref('')
const ruleForm = ref({
  name: '',
  field: 'path',
  header_name: '',
  operator: 'contains',
  value: '',
  action: 'block',
  priority: 0,
  enabled: true,
  expr: '',
})

const ipModalOpen = ref(false)
const ipError = ref('')
const ipForm = ref({ kind: 'deny', ip: '', note: '' })

const banModalOpen = ref(false)
const banError = ref('')
const banForm = ref({ domain: '', ip: '', seconds: 3600, reason: 'manual-cc-ban' })

const managedRules = [
  { key: 'sqli', label: 'SQL 注入', desc: 'union select、or 1=1、sleep() 等特征' },
  { key: 'xss', label: 'XSS 跨站脚本', desc: '\u003cscript\u003e、javascript:、onerror= 等' },
  { key: 'traversal', label: '路径穿越', desc: '路径跳转 ../、/etc/passwd 读取' },
  { key: 'scanners', label: '扫描器与敏感路径', desc: 'sqlmap/nikto UA、/.git/config 等' },
  { key: 'rce', label: '命令执行 / RCE', desc: ';wget、|bash、powershell、$() 等' },
  { key: 'ssrf', label: 'SSRF / 云元数据', desc: '169.254.169.254、metadata、gopher:// 等' },
  { key: 'xxe', label: 'XXE 外部实体', desc: '<!ENTITY、system "、file:///etc 等' },
  { key: 'log4shell', label: 'Log4Shell', desc: '${jndi:ldap://}、jndi:rmi、大小写混淆等' },
  { key: 'crlf', label: 'CRLF / 头注入', desc: '路径或查询串中的 \\r\\n、%0d%0a' },
  { key: 'ssti', label: '模板注入 SSTI', desc: '{{7*7}}、${7*7}、__class__、FreeMarker 等' },
  { key: 'nosql', label: 'NoSQL 注入', desc: '$ne / $gt / $where / $regex 等操作符注入' },
  { key: 'ldap', label: 'LDAP 注入', desc: '*)(uid=*、)(|(、objectClass=* 等' },
  { key: 'java', label: 'Java 反序列化 / OGNL', desc: 'ProcessBuilder、getRuntime、OGNL、Spring4Shell 等' },
  { key: 'webshell', label: 'WebShell / PHP 注入', desc: '<?php、php://filter、eval()、base64_decode() 等' },
  { key: 'protocol', label: '协议异常', desc: '空字节、双重编码、超长路径或查询串' },
]

const tabs = computed(() => [
  { value: 'overview' as Tab, label: '数据概览' },
  { value: 'settings' as Tab, label: '防护设置' },
  { value: 'rules' as Tab, label: '自定义规则', count: rules.value.length },
  { value: 'ips' as Tab, label: 'IP 黑白名单', count: ips.value.length },
  { value: 'bans' as Tab, label: '共享封禁', count: bans.value.length },
  { value: 'events' as Tab, label: '事件日志' },
])

function actionCount(action: string) {
  const row = (stats.value.by_action || []).find((r: any) => r.key === action)
  return row ? row.count : 0
}

const maxDayCount = computed(() => {
  const rows = stats.value.by_day || []
  return rows.reduce((m: number, r: any) => Math.max(m, r.count), 0) || 1
})

function barHeight(count: number) {
  return `${Math.max(4, Math.round((count / maxDayCount.value) * 100))}%`
}

async function loadStats() {
  if (!domainId.value) return
  statsLoading.value = true
  try {
    const name = domains.value.find((d) => d.id === domainId.value)?.name || ''
    const q = new URLSearchParams({ days: '7' })
    if (name) q.set('domain', name)
    stats.value = await api.get<any>(`/api/v1/waf/stats?${q.toString()}`)
    statsLoading.value = false
  } catch {
    stats.value = {
      days: 7,
      total: 0,
      by_action: [],
      by_category: [],
      by_day: [],
      top_ips: [],
      top_rules: [],
      top_paths: [],
    }
    statsLoading.value = false
  }
}

const filteredEvents = computed(() => {
  if (!eventAction.value) return events.value
  return events.value.filter((e) => e.action === eventAction.value)
})

const eventPage = ref(1)
const eventPageSize = 20
const pagedEvents = computed(() => {
  const start = (eventPage.value - 1) * eventPageSize
  return filteredEvents.value.slice(start, start + eventPageSize)
})
watch([eventAction, eventLimit], () => {
  eventPage.value = 1
})
watch(
  () => filteredEvents.value.length,
  (total) => {
    eventPage.value = Math.min(eventPage.value, Math.max(1, Math.ceil(total / eventPageSize)))
  },
)

function fieldLabel(field: string) {
  if (field && field.startsWith('header:')) return `请求头 ${field.slice(7)}`
  return (
    {
      path: '路径',
      query: '查询串',
      user_agent: 'UA',
      referer: 'Referer',
      method: '方法',
      ip: 'IP',
    } as Record<string, string>
  )[field] || field
}

function opLabel(op: string) {
  return ({ contains: '包含', equals: '等于', prefix: '前缀', suffix: '后缀' } as Record<string, string>)[op] || op
}

function actionLabel(action: string) {
  return (
    { block: '拦截', allow: '放行', log: '仅记录', challenge: '质询' } as Record<string, string>
  )[action] || action
}

function actionTone(action: string) {
  if (action === 'block') return 'danger'
  if (action === 'allow') return 'success'
  return 'info'
}

function eventLabel(action: string) {
  return (
    { block: '拦截', monitor: '观察', log: '记录', challenge: '质询' } as Record<string, string>
  )[action] || action
}

function eventTone(action: string) {
  return action === 'block' ? 'danger' : action === 'monitor' ? 'warning' : 'info'
}

function categoryLabel(category: string) {
  return (
    {
      sqli: 'SQL 注入',
      xss: 'XSS',
      traversal: '路径穿越',
      scanners: '扫描器',
      rce: '命令执行',
      ssrf: 'SSRF',
      xxe: 'XXE',
      log4shell: 'Log4Shell',
      crlf: 'CRLF 注入',
      ip_deny: 'IP 黑名单',
      custom: '自定义规则',
      security_level: '安全级别',
    } as Record<string, string>
  )[category] || category || '—'
}

async function loadDomains() {
  domains.value = (await api.get<any[]>('/api/v1/domains').catch(() => [])) || []
  if (!domainId.value && domains.value.length) {
    domainId.value = domains.value[0].id
  }
}

async function loadSettings() {
  if (!domainId.value) return
  try {
    const s = await api.get<any>(`/api/v1/domains/${domainId.value}/waf`)
    settings.value = {
      enabled: !!s.enabled,
      mode: s.mode === 'monitor' ? 'monitor' : 'block',
      sqli: !!s.sqli,
      xss: !!s.xss,
      traversal: !!s.traversal,
      scanners: !!s.scanners,
      rce: !!s.rce,
      ssrf: !!s.ssrf,
      xxe: !!s.xxe,
      log4shell: !!s.log4shell,
      crlf: !!s.crlf,
      ssti: !!s.ssti,
      nosql: !!s.nosql,
      ldap: !!s.ldap,
      java: !!s.java,
      webshell: !!s.webshell,
      protocol: !!s.protocol,
      security_level: s.security_level || 'off',
      challenge_difficulty: s.challenge_difficulty || 4,
      challenge_ttl_secs: s.challenge_ttl_secs || 1800,
      managed_rulesets: Array.isArray(s.managed_rulesets) ? s.managed_rulesets : [],
      waf_rulepack_version: s.waf_rulepack_version || '',
      waf_gray_percent: s.waf_gray_percent ?? 0,
    }
  } catch {
    settings.value = {
      enabled: false,
      mode: 'block',
      sqli: true,
      xss: true,
      traversal: true,
      scanners: true,
      rce: true,
      ssrf: true,
      xxe: true,
      log4shell: true,
      crlf: true,
      security_level: 'off',
      challenge_difficulty: 4,
      challenge_ttl_secs: 1800,
      managed_rulesets: [],
      waf_rulepack_version: '',
      waf_gray_percent: 0,
    }
  }
}

async function loadRulesets() {
  rulesets.value = (await api.get<any[]>('/api/v1/waf/rulesets').catch(() => [])) || []
}

function slotLabel(slot: string) {
  return ({ active: '当前版本', previous: '上一版本', retired: '已退役' } as Record<string, string>)[slot] || slot
}

function formatRulepackTime(value: string) {
  if (!value) return ''
  return value.slice(0, 16).replace('T', ' ')
}

async function loadRulepacks() {
  rulepackVersions.value = (await api.get<any[]>('/api/v1/waf/rulepacks').catch(() => [])) || []
}

async function publishRulepack() {
  rulepackBusy.value = true
  try {
    await api.post('/api/v1/waf/rulepacks/publish', {})
    toast.success('新规则包已发布并签名')
    await loadRulepacks()
  } catch (e: any) {
    toast.error(e?.data?.error || '发布失败')
  } finally {
    rulepackBusy.value = false
  }
}

async function retireRulepack(version: string) {
  const ok = await ask({
    title: '转为 retired',
    text: `将规则包 ${version} 转为 retired？转为 retired 后才能删除。`,
    confirmText: '转为 retired',
  })
  if (!ok) return
  rulepackBusy.value = true
  try {
    await api.post(`/api/v1/waf/rulepacks/${version}/retire`, {})
    toast.success(`规则包 ${version} 已转为 retired`)
    await loadRulepacks()
  } catch (e: any) {
    toast.error(e?.data?.error || '操作失败')
  } finally {
    rulepackBusy.value = false
  }
}

async function deleteRulepack(version: string) {
  const ok = await ask({
    title: '删除规则包',
    text: `删除规则包 ${version}？此操作不可撤销；仍有域名固定该版本时会被拒绝。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  rulepackBusy.value = true
  try {
    await api.del(`/api/v1/waf/rulepacks/${version}`)
    toast.success(`规则包 ${version} 已删除`)
    await loadRulepacks()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  } finally {
    rulepackBusy.value = false
  }
}

async function rollbackRulepack(version: string) {
  rulepackBusy.value = true
  try {
    await api.post(`/api/v1/waf/rulepacks/${version}/rollback`, {})
    toast.success(`规则包已切换到 ${version}`)
    await loadRulepacks()
  } catch (e: any) {
    toast.error(e?.data?.error || '回滚失败')
  } finally {
    rulepackBusy.value = false
  }
}

function toggleRuleset(id: string) {
  const selected = settings.value.managed_rulesets || []
  settings.value.managed_rulesets = selected.includes(id)
    ? selected.filter((item: string) => item !== id)
    : [...selected, id]
}

async function loadRules() {
  if (!domainId.value) return
  rules.value = (await api.get<any[]>(`/api/v1/domains/${domainId.value}/waf/rules`).catch(() => [])) || []
}

async function loadIps() {
  if (!domainId.value) return
  ips.value = (await api.get<any[]>(`/api/v1/domains/${domainId.value}/waf/ips`).catch(() => [])) || []
}

async function loadEvents() {
  if (!domainId.value) return
  eventsLoading.value = true
  try {
    const q = new URLSearchParams({
      domain: domains.value.find((d) => d.id === domainId.value)?.name || '',
      limit: String(eventLimit.value),
    })
    events.value = (await api.get<any[]>(`/api/v1/waf/events?${q.toString()}`)) || []
  } catch {
    events.value = []
  } finally {
    eventsLoading.value = false
  }
}

async function loadBans() {
  bansError.value = ''
  if (!currentDomainName.value) {
    bans.value = []
    ccStats.value = null
    return
  }
  bansLoading.value = true
  try {
    const q = new URLSearchParams()
    q.set('domain', currentDomainName.value)
    q.set('limit', '500')
    const suffix = `?${q.toString()}`
    const res = await api.get<{ bans: any[] }>(`/api/v1/cc/bans/history${suffix}`)
    bans.value = res.bans || []
    if (auth.isAdmin) {
      const statsSuffix = `?domain=${encodeURIComponent(currentDomainName.value)}`
      ccStats.value = await api.get<any>(`/api/v1/cc/stats${statsSuffix}`).catch(() => null)
    } else {
      ccStats.value = null
    }
  } catch (e: any) {
    bans.value = []
    ccStats.value = null
    const status = e?.response?.status ?? e?.status
    bansError.value =
      status === 404
        ? '控制面未提供封禁历史接口，请升级并重启 lagran-control。'
        : status >= 500
          ? '加载封禁历史失败，请检查控制面日志和数据库迁移是否完成。'
          : friendlyErrorMessage(e?.data?.error, '加载封禁历史失败，请稍后重试')
  } finally {
    bansLoading.value = false
  }
}

function openBanModal() {
  banError.value = ''
  banForm.value = {
    domain: currentDomainName.value,
    ip: '',
    seconds: 3600,
    reason: 'manual-cc-ban',
  }
  banModalOpen.value = true
}

async function saveBan() {
  banError.value = ''
  if (!banForm.value.domain.trim()) {
    banError.value = '请选择域名'
    return
  }
  if (!banForm.value.ip.trim()) {
    banError.value = '请填写 IP 或 CIDR'
    return
  }
  saving.value = true
  try {
    await api.post('/api/v1/cc/bans/manual', {
      domain: banForm.value.domain.trim(),
      ip: banForm.value.ip.trim(),
      seconds: Number(banForm.value.seconds) || 3600,
      reason: banForm.value.reason.trim(),
    })
    banModalOpen.value = false
    toast.success('已添加共享封禁，边缘约 5 秒内同步')
    await loadBans()
  } catch (e: any) {
    banError.value = e?.data?.error || '添加封禁失败'
  } finally {
    saving.value = false
  }
}

function banStatusLabel(status: string) {
  if (status === 'active') return '生效中'
  if (status === 'revoked') return '已解封'
  return '已过期'
}

function banTone(status: string) {
  if (status === 'active') return 'danger'
  if (status === 'revoked') return 'info'
  return 'neutral'
}

function remainingLabel(seconds: number) {
  const s = Math.max(0, Number(seconds) || 0)
  if (s < 60) return `${s} 秒`
  if (s < 3600) return `${Math.ceil(s / 60)} 分钟`
  return `${Math.floor(s / 3600)} 小时 ${Math.ceil((s % 3600) / 60)} 分`
}

async function unbanIp(ban: any) {
  const ok = await ask({
    title: '解除共享封禁',
    message: `确认解封 ${ban.domain} 的 ${ban.ip}？所有边缘节点会在下一轮同步时解除。`,
    confirmText: '解封',
    danger: true,
  })
  if (!ok) return
  try {
    await api.post('/api/v1/cc/bans/unban', {
      domain: ban.domain,
      ip: ban.ip,
    })
    toast.success('已解封，边缘节点将在约 5 秒内同步')
    await loadBans()
  } catch (e: any) {
    toast.error(e?.data?.error || '解封失败')
  }
}

async function reload() {
  loading.value = true
  try {
    await loadDomains()
    await loadRulesets()
    await loadRulepacks()
    await Promise.all([loadSettings(), loadRules(), loadIps(), loadBans()])
    if (tab.value === 'events') await loadEvents()
    if (tab.value === 'overview') await loadStats()
  } finally {
    loading.value = false
  }
}

async function switchTab(next: Tab) {
  tab.value = next
  if (next === 'events') await loadEvents()
  if (next === 'rules') await loadRules()
  if (next === 'ips') await loadIps()
  if (next === 'bans') await loadBans()
  if (next === 'settings') await loadSettings()
  if (next === 'overview') await loadStats()
}

async function saveSettings() {
  if (!domainId.value) return
  saving.value = true
  try {
    const s = await api.put<any>(`/api/v1/domains/${domainId.value}/waf`, settings.value)
    settings.value = {
      enabled: !!s.enabled,
      mode: s.mode === 'monitor' ? 'monitor' : 'block',
      sqli: !!s.sqli,
      xss: !!s.xss,
      traversal: !!s.traversal,
      scanners: !!s.scanners,
      rce: !!s.rce,
      ssrf: !!s.ssrf,
      xxe: !!s.xxe,
      log4shell: !!s.log4shell,
      crlf: !!s.crlf,
      ssti: !!s.ssti,
      nosql: !!s.nosql,
      ldap: !!s.ldap,
      java: !!s.java,
      webshell: !!s.webshell,
      protocol: !!s.protocol,
      security_level: s.security_level || 'off',
      challenge_difficulty: s.challenge_difficulty || 4,
      challenge_ttl_secs: s.challenge_ttl_secs || 1800,
      managed_rulesets: Array.isArray(s.managed_rulesets) ? s.managed_rulesets : [],
      waf_rulepack_version: s.waf_rulepack_version || '',
      waf_gray_percent: s.waf_gray_percent ?? 0,
    }
    toast.success('WAF 设置已保存，边缘约 15 秒内同步')
  } catch (e: any) {
    toast.error(e?.data?.error || '保存失败')
  } finally {
    saving.value = false
  }
}

function openRuleModal(rule?: any) {
  ruleError.value = ''
  editingRule.value = rule || null
  ruleForm.value = rule
    ? {
        name: rule.name,
        field: rule.field && rule.field.startsWith('header:') ? 'header' : rule.field,
        header_name: rule.field && rule.field.startsWith('header:') ? rule.field.slice(7) : '',
        operator: rule.operator,
        value: rule.value,
        action: rule.action,
        priority: rule.priority,
        enabled: rule.enabled,
        expr: rule.expr || '',
      }
    : {
        name: '',
        field: 'path',
        header_name: '',
        operator: 'contains',
        value: '',
        action: 'block',
        priority: 0,
        enabled: true,
        expr: '',
      }
  ruleModalOpen.value = true
}

const dslTextarea = ref<HTMLTextAreaElement | null>(null)
const dslSuggestOpen = ref(false)
const dslSuggestions = ref<{ label: string; insert: string; detail: string; back?: number }[]>([])
const dslSuggestIndex = ref(0)
const dslTokenStart = ref(0)

const DSL_FIELDS = [
  { label: 'path', insert: 'path ', detail: '请求路径' },
  { label: 'query', insert: 'query ', detail: '查询串' },
  { label: 'user_agent', insert: 'user_agent ', detail: 'User-Agent' },
  { label: 'referer', insert: 'referer ', detail: 'Referer' },
  { label: 'method', insert: 'method ', detail: '请求方法' },
  { label: 'ip', insert: 'ip ', detail: '客户端 IP' },
  { label: 'header:', insert: 'header:', detail: '请求头' },
]
const DSL_OPS = [
  { label: 'contains', insert: 'contains ', detail: '包含' },
  { label: 'equals', insert: 'equals ', detail: '等于' },
  { label: 'prefix', insert: 'prefix ', detail: '前缀' },
  { label: 'suffix', insert: 'suffix ', detail: '后缀' },
]
const DSL_KEYWORDS = [
  { label: 'AND', insert: 'AND ', detail: '同时满足' },
  { label: 'OR', insert: 'OR ', detail: '任一满足' },
  { label: 'NOT', insert: 'NOT ', detail: '取反' },
]

function dslFieldKeys() {
  return DSL_FIELDS.map((f) => f.label.replace(':', ''))
}
function dslOpKeys() {
  return [...DSL_OPS.map((o) => o.label), 'in']
}
function insideDslString(before: string) {
  let quote = ''
  let escaped = false
  for (const ch of before) {
    if (escaped) {
      escaped = false
      continue
    }
    if (ch === '\\') {
      escaped = true
      continue
    }
    if (quote) {
      if (ch === quote) quote = ''
    } else if (ch === '"' || ch === "'") {
      quote = ch
    }
  }
  return !!quote
}

function updateDslSuggestions() {
  const el = dslTextarea.value
  if (!el) return
  const value = ruleForm.value.expr || ''
  const caret = el.selectionStart ?? value.length
  const before = value.slice(0, caret)
  if (insideDslString(before)) {
    dslSuggestOpen.value = false
    return
  }
  const tokenMatch = before.match(/[A-Za-z_][A-Za-z0-9_:-]*$/)
  const token = tokenMatch?.[0] ?? ''
  const start = tokenMatch ? caret - token.length : caret
  dslTokenStart.value = start
  const prior = before.slice(0, start).trimEnd()
  const prev = (prior.match(/[A-Za-z_][A-Za-z0-9_:-]*$/) || [])[0]?.toLowerCase() || ''
  const fields = dslFieldKeys()
  const ops = dslOpKeys()
  let candidates: { label: string; insert: string; detail: string; back?: number }[] = []

  if (fields.includes(prev) || prev.startsWith('header:')) {
    candidates = prev === 'ip'
      ? [...DSL_OPS, { label: 'in', insert: 'in ', detail: 'CIDR 网段' }]
      : DSL_OPS
  } else if (ops.includes(prev)) {
    candidates = prev === 'in'
      ? [{ label: '"10.0.0.0/8"', insert: '"10.0.0.0/8"', detail: 'CIDR' }]
      : [{ label: '""', insert: '""', detail: '字符串', back: 1 }]
  } else if (prev === 'and' || prev === 'or' || prev === 'not' || prior === '' || prior.endsWith('(')) {
    candidates = [...DSL_FIELDS, ...DSL_KEYWORDS]
  } else if (prior.endsWith(')') || prior.endsWith('"') || prior.endsWith("'")) {
    candidates = DSL_KEYWORDS
  } else {
    candidates = [...DSL_FIELDS, ...DSL_KEYWORDS]
  }

  const lower = token.toLowerCase()
  dslSuggestions.value = candidates.filter((item) =>
    item.label.toLowerCase().startsWith(lower)
  )
  dslSuggestIndex.value = 0
  dslSuggestOpen.value = dslSuggestions.value.length > 0
}

function closeDslSuggestionsSoon() {
  window.setTimeout(() => {
    dslSuggestOpen.value = false
  }, 120)
}

function applyDslSuggestion(item: { label: string; insert: string; back?: number }) {
  const el = dslTextarea.value
  if (!el) return
  const value = ruleForm.value.expr || ''
  const caret = el.selectionStart ?? value.length
  const start = dslTokenStart.value
  const next = value.slice(0, start) + item.insert + value.slice(caret)
  ruleForm.value.expr = next
  dslSuggestOpen.value = false
  nextTick(() => {
    const pos = start + item.insert.length - (item.back || 0)
    el.focus()
    el.setSelectionRange(pos, pos)
  })
}

function onDslKeydown(event: KeyboardEvent) {
  if (!dslSuggestOpen.value || !dslSuggestions.value.length) return
  if (event.key === 'ArrowDown') {
    event.preventDefault()
    dslSuggestIndex.value = (dslSuggestIndex.value + 1) % dslSuggestions.value.length
  } else if (event.key === 'ArrowUp') {
    event.preventDefault()
    dslSuggestIndex.value =
      (dslSuggestIndex.value - 1 + dslSuggestions.value.length) % dslSuggestions.value.length
  } else if (event.key === 'Enter' || event.key === 'Tab') {
    event.preventDefault()
    applyDslSuggestion(dslSuggestions.value[dslSuggestIndex.value])
  } else if (event.key === 'Escape') {
    dslSuggestOpen.value = false
  }
}

async function saveRule() {
  ruleError.value = ''
  const usingDsl = !!ruleForm.value.expr.trim()
  if (!ruleForm.value.name.trim() || (!usingDsl && !ruleForm.value.value.trim())) {
    ruleError.value = usingDsl ? '请填写规则名称' : '请填写规则名称与匹配内容'
    return
  }
  if (!usingDsl && ruleForm.value.field === 'header' && !ruleForm.value.header_name.trim()) {
    ruleError.value = '请填写要匹配的请求头名称'
    return
  }
  saving.value = true
  try {
    const { header_name, ...rest } = ruleForm.value
    const body = {
      ...rest,
      field: ruleForm.value.field === 'header' ? `header:${header_name.trim()}` : ruleForm.value.field,
    }
    if (editingRule.value) {
      await api.put(`/api/v1/waf/rules/${editingRule.value.id}`, body)
      toast.success('规则已更新')
    } else {
      await api.post(`/api/v1/domains/${domainId.value}/waf/rules`, body)
      toast.success('规则已创建')
    }
    ruleModalOpen.value = false
    await loadRules()
  } catch (e: any) {
    ruleError.value = e?.data?.error || '保存失败'
  } finally {
    saving.value = false
  }
}

async function toggleRule(rule: any) {
  try {
    await api.put(`/api/v1/waf/rules/${rule.id}`, {
      name: rule.name,
      field: rule.field,
      operator: rule.operator,
      value: rule.value,
      action: rule.action,
      priority: rule.priority,
      enabled: !rule.enabled,
      expr: rule.expr || '',
    })
    await loadRules()
  } catch (e: any) {
    toast.error(e?.data?.error || '更新失败')
  }
}

async function removeRule(rule: any) {
  const ok = await ask({
    title: '删除 WAF 规则',
    message: `确认删除「${rule.name}」？删除后立即生效（边缘约 15 秒内同步）。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/waf/rules/${rule.id}`)
    toast.success('规则已删除')
    await loadRules()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

function openIpModal(kind: 'allow' | 'deny') {
  ipError.value = ''
  ipForm.value = { kind, ip: '', note: '' }
  ipModalOpen.value = true
}

async function saveIp() {
  ipError.value = ''
  if (!ipForm.value.ip.trim()) {
    ipError.value = '请填写 IP 或 CIDR'
    return
  }
  saving.value = true
  try {
    await api.post(`/api/v1/domains/${domainId.value}/waf/ips`, ipForm.value)
    ipModalOpen.value = false
    toast.success('IP 名单已添加')
    await loadIps()
  } catch (e: any) {
    ipError.value = e?.data?.error || '添加失败，请检查 IP 格式'
  } finally {
    saving.value = false
  }
}

async function removeIp(ip: any) {
  const ok = await ask({
    title: '删除 IP 名单',
    message: `确认删除 ${ip.ip}（${ip.kind === 'allow' ? '白名单' : '黑名单'}）？`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/waf/ips/${ip.id}`)
    toast.success('已删除')
    await loadIps()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

watch(domainId, async (id) => {
  if (!id) return
  loading.value = true
  try {
    await Promise.all([loadSettings(), loadRules(), loadIps(), loadBans()])
    if (tab.value === 'events') await loadEvents()
    if (tab.value === 'overview') await loadStats()
  } finally {
    loading.value = false
  }
})

watch([eventAction, eventLimit], () => {
  if (tab.value === 'events') loadEvents()
})

onMounted(reload)
</script>

<style scoped>
.cc-stat-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--divider);
  background: var(--bg);
}

.cc-stat {
  color: var(--text-3);
  font-size: 12px;
  padding: 4px 10px;
  border: 1px solid var(--border);
  border-radius: 999px;
  background: var(--card);
}

.cc-stat b {
  color: var(--text);
  margin-right: 3px;
}

.waf-toolbar {
  padding: 14px 18px;
  margin-bottom: 16px;
}

.waf-tabs {
  display: flex;
  gap: 4px;
  padding: 0 18px;
  border-bottom: 1px solid var(--divider);
  overflow-x: auto;
}

.waf-tab {
  position: relative;
  border: none;
  background: transparent;
  padding: 14px 12px 12px;
  font-size: 14px;
  color: var(--text-2);
  cursor: pointer;
  border-bottom: 2px solid transparent;
  white-space: nowrap;
}

.waf-tab:hover {
  color: var(--brand);
}

.waf-tab.active {
  color: var(--brand);
  font-weight: 500;
  border-bottom-color: var(--brand);
}

.tab-count {
  margin-left: 4px;
  font-size: 11px;
  color: var(--text-3);
}

.bar-chart {
  display: flex;
  align-items: flex-end;
  gap: 6px;
  height: 150px;
  padding: 12px 4px 0;
  border-bottom: 1px solid var(--divider);
}

.bar-col {
  flex: 1;
  min-width: 8px;
  height: 100%;
  display: flex;
  flex-direction: column;
  justify-content: flex-end;
  align-items: center;
  gap: 6px;
}

.bar {
  width: 100%;
  max-width: 28px;
  background: linear-gradient(180deg, #3b82f6, #2563eb);
  border-radius: 3px 3px 0 0;
  transition: height 0.2s ease;
}

.bar-label {
  font-size: 10px;
  color: var(--text-3);
  white-space: nowrap;
}

.waf-stat-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin-top: 20px;
}

.stat-list {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px 14px;
  min-height: 120px;
}

.stat-list-title {
  font-size: 12px;
  color: var(--text-3);
  margin-bottom: 8px;
}

.stat-list-row {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  padding: 4px 0;
  font-size: 12.5px;
  color: var(--text-2);
}

.stat-list-row b {
  font-weight: 500;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}

.stat-empty {
  font-size: 12px;
  color: var(--text-4);
}

.truncate {
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.level-seg {
  flex-wrap: wrap;
}

@media (max-width: 900px) {
  .waf-stat-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

.setting-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 14px 0;
  border-bottom: 1px solid var(--divider);
}

.setting-title {
  font-size: 14px;
  color: var(--text);
}

.setting-desc {
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
}

.section-label {
  margin: 20px 0 10px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-2);
}

.managed-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.managed-item {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  cursor: pointer;
  transition: all 0.15s ease;
}

.managed-item.on {
  border-color: #bedaff;
  background: #f7faff;
}

.managed-item input {
  margin-top: 3px;
  accent-color: var(--brand);
}

.managed-info {
  flex: 1;
  min-width: 0;
}

.managed-info strong {
  display: block;
  font-size: 13.5px;
  font-weight: 500;
  color: var(--text);
}

.managed-info small {
  display: block;
  margin-top: 2px;
  font-size: 12px;
  color: var(--text-3);
  line-height: 1.5;
}

.managed-item .app-icon {
  color: var(--text-4);
}

.managed-item.on .app-icon {
  color: var(--brand);
}

/* managed rulesets */
.ruleset-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.ruleset-card {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  background: var(--card);
  cursor: pointer;
  transition: border-color 0.15s ease, box-shadow 0.15s ease;
}

.ruleset-card:hover {
  border-color: var(--border-strong);
}

.ruleset-card.on {
  border-color: var(--brand-bg-strong);
  background: var(--brand-bg);
  box-shadow: 0 4px 14px rgba(37, 99, 235, 0.06);
}

.ruleset-card input {
  margin-top: 3px;
  accent-color: var(--brand);
}

.ruleset-body {
  flex: 1;
  min-width: 0;
}

.ruleset-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}

.ruleset-head strong {
  font-size: 13.5px;
  color: var(--text);
}

.ruleset-version {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text-3);
}

.ruleset-badge {
  font-size: 11px;
  line-height: 18px;
  padding: 0 7px;
  border-radius: 9px;
  color: var(--brand);
  background: var(--brand-bg);
}

.ruleset-body small {
  display: block;
  margin-top: 5px;
  font-size: 12px;
  line-height: 1.55;
  color: var(--text-3);
}

.ruleset-categories {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-top: 9px;
}

.ruleset-chip {
  font-size: 11px;
  line-height: 20px;
  padding: 0 7px;
  border-radius: 10px;
  background: var(--bg);
  color: var(--text-2);
}

.ruleset-card .app-icon {
  color: var(--text-4);
}

.ruleset-card.on .app-icon {
  color: var(--brand);
}

/* rulepack version / rollout */
.rulepack-admin {
  margin-top: 14px;
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.rulepack-versions {
  margin-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.rulepack-version-row {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 11px 12px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--card);
  transition: border-color 0.15s ease, background 0.15s ease;
}

.rulepack-version-row:hover {
  border-color: var(--border-strong);
  background: var(--bg);
}

.rulepack-version-row.slot-active {
  border-color: var(--brand-bg-strong);
  background: var(--brand-bg);
}

.version-main {
  flex: 1;
  min-width: 0;
}

.version-title {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.version-name {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
}

.slot-badge {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  height: 20px;
  padding: 0 8px;
  border-radius: 10px;
  font-size: 11px;
  line-height: 20px;
}

.slot-dot {
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: currentColor;
}

.slot-badge-active {
  color: var(--success);
  background: var(--success-bg);
}

.slot-badge-previous {
  color: var(--warning);
  background: var(--warning-bg);
}

.slot-badge-retired {
  color: var(--text-3);
  background: var(--bg);
}

.version-meta {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-top: 4px;
  font-size: 11.5px;
  color: var(--text-3);
}

.meta-sep {
  color: var(--text-4);
}

.version-actions {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  flex-wrap: wrap;
  gap: 6px;
  flex: none;
}

.version-action {
  min-width: 82px;
}

.current-label {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  color: var(--success);
  font-size: 12px;
  white-space: nowrap;
}

/* custom rule DSL */
.dsl-editor {
  position: relative;
}

.dsl-suggest {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  z-index: 40;
  max-height: 220px;
  overflow-y: auto;
  background: var(--card);
  border: 1px solid var(--border-strong);
  border-radius: 9px;
  box-shadow: var(--shadow);
  padding: 4px;
}

.dsl-suggest-item {
  display: flex;
  align-items: center;
  gap: 10px;
  width: 100%;
  padding: 7px 9px;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--text-2);
  font-size: 12px;
  text-align: left;
  cursor: pointer;
}

.dsl-suggest-item:hover,
.dsl-suggest-item.active {
  background: var(--brand-bg);
  color: var(--brand);
}

.dsl-suggest-label {
  font-weight: 600;
  color: var(--text);
}

.dsl-suggest-item.active .dsl-suggest-label {
  color: var(--brand);
}

.dsl-suggest-detail {
  margin-left: auto;
  font-size: 11px;
  color: var(--text-3);
}

.dsl-suggest-foot {
  padding: 6px 9px 3px;
  font-size: 10.5px;
  color: var(--text-3);
  border-top: 1px solid var(--divider);
  margin-top: 3px;
}
.dsl-cell {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 11.5px;
}

.dsl-badge {
  flex: none;
  padding: 0 5px;
  border-radius: 4px;
  background: var(--brand-bg);
  color: var(--brand);
  font-family: var(--font);
  font-size: 10px;
  line-height: 18px;
}

@media (max-width: 900px) {
  .managed-grid,
  .ruleset-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .rulepack-version-row {
    align-items: flex-start;
    flex-direction: column;
    gap: 10px;
  }

  .version-actions {
    width: 100%;
    justify-content: flex-start;
  }
}
</style>
