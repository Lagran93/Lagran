<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">边缘节点</div>
        <div class="page-desc">
          预注册节点、生成安装命令、启停与下线；节点每 15 秒上报心跳，60 秒无心跳记为离线
        </div>
      </div>
      <div class="page-actions">
        <label class="switch" :class="{ on: autoRefresh }">
          <span class="switch-track" />
          <input v-model="autoRefresh" type="checkbox" style="display: none" />
          自动刷新
        </label>
        <button class="btn btn-default" type="button" @click="exportNodes">
          <AppIcon name="upload" :size="15" />
          导出 CSV
        </button>
        <button class="btn btn-default" type="button" :disabled="loading" @click="load">
          <AppIcon name="refresh" :size="15" />
          刷新
        </button>
        <button class="btn btn-default" type="button" @click="openSchedule">
          <AppIcon name="globe" :size="15" />
          调度测试
        </button>
        <button class="btn btn-default" type="button" @click="openDnsTest">
          <AppIcon name="search" :size="15" />
          DNS 测试
        </button>
        <NuxtLink to="/nodes/onboard" class="btn btn-default">
          <AppIcon name="zap" :size="15" />
          新增 Edge 向导
        </NuxtLink>
      </div>
    </div>

    <div class="stat-grid">
      <StatCard label="节点总数" :value="nodes.length" icon="node" />
      <StatCard label="在线节点" :value="counts.online" icon="activity" tone="green" />
      <StatCard label="待接入 / 离线" :value="counts.pending + counts.offline" hint="安装后等待首次心跳" icon="clock" tone="orange" />
      <StatCard label="已停用" :value="counts.disabled" icon="alert" tone="red" />
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">节点列表</div>
          <div class="card-desc">停用后节点立即停止代理流量，但仍保留心跳与管理接口</div>
        </div>
        <div class="card-extra text-muted" style="font-size: 12px">
          {{ lastUpdated ? `更新于 ${lastUpdated}` : '' }}
        </div>
      </div>

      <div v-if="nodes.length" class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="min-width: 190px">节点</th>
              <th>区域 / 线路</th>
              <th>状态</th>
              <th class="num">版本</th>
              <th style="min-width: 150px">资源</th>
              <th style="min-width: 190px">Agent 地址</th>
              <th style="min-width: 140px">最后心跳</th>
              <th style="min-width: 230px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="n in pagedNodes" :key="n.id">
              <td>
                <div class="cell-main">{{ n.name }}</div>
                <div class="cell-sub mono">{{ n.id.slice(0, 8) }}</div>
              </td>
              <td>
                <div>{{ n.region || '默认区域' }}</div>
                <div class="cell-sub">
                  {{ [n.country, n.province, n.city, n.isp].filter(Boolean).join(' · ') || '未设置线路' }}
                </div>
                <div class="cell-sub mono">{{ n.public_ip || '未设置公网 IP' }}</div>
              </td>
              <td>
                <StatusTag :tone="statusTone(n.status)" dot>
                  {{ statusLabel(n.status) }}
                </StatusTag>
              </td>
              <td class="num text-2">{{ n.version || '—' }}</td>
              <td>
                <div class="resource">
                  <span class="res-label">CPU</span>
                  <div class="progress res-bar">
                    <div class="progress-bar"
                      :style="{ width: `${n.cpu_usage ?? 0}%`, background: usageColor(n.cpu_usage) }" />
                  </div>
                  <span class="res-val">{{ n.cpu_usage != null ? `${n.cpu_usage.toFixed(0)}%` : '—' }}</span>
                </div>
                <div class="resource">
                  <span class="res-label">MEM</span>
                  <div class="progress res-bar">
                    <div class="progress-bar"
                      :style="{ width: `${n.memory_usage ?? 0}%`, background: usageColor(n.memory_usage) }" />
                  </div>
                  <span class="res-val">{{ n.memory_usage != null ? `${n.memory_usage.toFixed(0)}%` : '—' }}</span>
                </div>
              </td>
              <td>
                <span class="mono text-2">{{ n.agent_url || '—' }}</span>
              </td>
              <td>
                <div>{{ fromNow(n.last_heartbeat) }}</div>
                <div class="cell-sub">{{ formatDateTime(n.last_heartbeat) }}</div>
              </td>
              <td>
                <div class="ops">
                  <button class="btn btn-text btn-sm" type="button" @click="openDetail(n)">
                    详情
                  </button>
                  <button class="btn btn-text btn-sm" type="button" :disabled="upgradingId === n.id"
                    @click="upgrade(n)">
                    {{ upgradingId === n.id ? '升级中…' : '升级' }}
                  </button>
                  <button class="btn btn-text btn-sm" type="button" @click="openEdit(n)">
                    编辑
                  </button>
                  <button class="btn btn-text btn-sm" type="button" @click="toggle(n)">
                    {{ n.status === 'disabled' ? '启用' : '停用' }}
                  </button>
                  <button class="btn btn-text btn-sm danger" type="button" @click="remove(n)">
                    删除
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div v-if="nodes.length > pageSize" class="table-footer">
        <AppPagination v-model:page="page" :total="nodes.length" :page-size="pageSize" />
      </div>

      <div v-if="!nodes.length && loading" class="card-body">
        <div class="skeleton" style="height: 34px; width: 100%" />
      </div>

      <EmptyState v-else-if="!nodes.length" icon="node" title="还没有边缘节点"
        text="先用「新增 Edge 向导」按服务器硬件生成适配的 edge.env；注册节点后在服务器上应用该配置并启动，约 15 秒自动上线。">
        <NuxtLink to="/nodes/onboard" class="btn btn-primary btn-sm">
          打开新增 Edge 向导
        </NuxtLink>
      </EmptyState>
    </div>

    <!-- 编辑节点（新增统一走「新增 Edge 向导」） -->
    <BaseModal v-model="formOpen" title="编辑节点" confirm-text="保存修改" :loading="saving"
      @confirm="submitForm">
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">节点名称 <span class="req">*</span></label>
            <input v-model="form.name" class="input" placeholder="例如 edge-hk-01" disabled />
            <span class="field-hint">
              名称用于心跳标识，无法修改；改名请删除节点后通过向导重新接入。
            </span>
          </div>
          <div class="field">
            <label class="field-label">区域</label>
            <input v-model="form.region" class="input" placeholder="例如 cn-hongkong" />
          </div>
          <div class="field">
            <label class="field-label">国家/地区代码</label>
            <input v-model="form.country" class="input" list="node-country-codes" maxlength="2" placeholder="CN" />
            <datalist id="node-country-codes">
              <option value="CN">中国大陆</option>
              <option value="HK">中国香港</option>
              <option value="MO">中国澳门</option>
              <option value="TW">中国台湾</option>
              <option value="JP">日本</option>
              <option value="KR">韩国</option>
              <option value="SG">新加坡</option>
              <option value="US">美国</option>
              <option value="GB">英国</option>
              <option value="DE">德国</option>
              <option value="FR">法国</option>
              <option value="NL">荷兰</option>
              <option value="CA">加拿大</option>
              <option value="AU">澳大利亚</option>
              <option value="RU">俄罗斯</option>
            </datalist>
            <span class="field-hint">ISO 3166-1 两位代码，需与 ip2region 返回的 country 一致，如 CN / HK / US。</span>
          </div>
          <div class="field">
            <label class="field-label">公网 IP</label>
            <input v-model="form.public_ip" class="input" placeholder="DNS 调度返回的 IP" />
          </div>
          <div class="field">
            <label class="field-label">省份</label>
            <input v-model="form.province" class="input" placeholder="例如 广东" />
          </div>
          <div class="field">
            <label class="field-label">城市</label>
            <input v-model="form.city" class="input" placeholder="例如 深圳" />
          </div>
          <div class="field">
            <label class="field-label">运营商</label>
            <input v-model="form.isp" class="input" placeholder="电信 / 联通 / 移动 / BGP" />
          </div>
          <div class="field">
            <label class="field-label">调度权重</label>
            <input v-model.number="form.weight" class="input" type="number" min="0" max="1000" />
            <span class="field-hint">数值越大越优先，默认 100。</span>
          </div>
          <div class="field span-2">
            <label class="field-label">Agent 地址</label>
            <input :value="form.agent_url" class="input mono" readonly />
            <span class="field-hint">
              控制面回调地址必须与 EDGE_ADMIN_LISTEN 成对修改；请到「详情 → 调整硬件画像」维护，
              保存时会校验端口并同步更新节点。
            </span>
          </div>
        </div>
        <p v-if="formError" class="text-danger" style="font-size: 13px">{{ formError }}</p>
      </div>
    </BaseModal>

    <!-- 节点详情 -->
    <BaseDrawer v-model="detailOpen" :title="`节点 · ${detail?.node?.name || ''}`" :close-on-overlay="true">
      <template #footer>
        <button class="btn btn-default" type="button" @click="detailOpen = false">关闭</button>
        <button v-if="detail" class="btn" :class="detail.node.status === 'disabled' ? 'btn-primary' : 'btn-default'"
          type="button" @click="toggle(detail.node)">
          {{ detail.node.status === 'disabled' ? '启用节点' : '停用节点' }}
        </button>
      </template>

      <div v-if="detail" class="form-col">
        <div class="detail-grid">
          <div class="detail-item">
            <div class="detail-label">节点 ID</div>
            <div class="detail-value mono">{{ detail.node.id }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">状态</div>
            <div class="detail-value">
              <StatusTag :tone="statusTone(detail.node.status)" dot>
                {{ statusLabel(detail.node.status) }}
              </StatusTag>
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">区域</div>
            <div class="detail-value">{{ detail.node.region || '默认区域' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">版本</div>
            <div class="detail-value">{{ detail.node.version || '—' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">公网 IP</div>
            <div class="detail-value mono">{{ detail.node.public_ip || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">国家/地区</div>
            <div class="detail-value">{{ detail.node.country || 'CN' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">省份 / 城市</div>
            <div class="detail-value">
              {{ [detail.node.province, detail.node.city].filter(Boolean).join(' / ') || '未配置' }}
            </div>
          </div>
          <div class="detail-item">
            <div class="detail-label">运营商</div>
            <div class="detail-value">{{ detail.node.isp || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">调度权重</div>
            <div class="detail-value">{{ detail.node.weight ?? 100 }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">节点 IP</div>
            <div class="detail-value mono">{{ detail.node.ip || '—' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">创建时间</div>
            <div class="detail-value">{{ formatDateTime(detail.node.created_at) }}</div>
          </div>
          <div class="detail-item span-2">
            <div class="detail-label">Agent 地址</div>
            <div class="detail-value mono">{{ detail.node.agent_url || '未配置' }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">最后心跳</div>
            <div class="detail-value">{{ formatDateTime(detail.node.last_heartbeat) }}</div>
          </div>
          <div class="detail-item">
            <div class="detail-label">资源占用</div>
            <div class="detail-value">
              CPU {{ detail.node.cpu_usage != null ? `${detail.node.cpu_usage.toFixed(0)}%` : '—' }}
              · MEM {{ detail.node.memory_usage != null ? `${detail.node.memory_usage.toFixed(0)}%` : '—' }}
            </div>
          </div>
        </div>

        <div class="section-title">节点令牌</div>
        <div class="copy-row">
          <input class="input mono" :value="detail.token" readonly />
          <button class="btn btn-default" type="button" @click="copy(detail.token, '令牌')">
            <AppIcon name="copy" :size="15" />
            复制
          </button>
        </div>

        <div class="section-title">edge.env 配置文件</div>
        <div v-if="!detailProfileStored" class="alert alert-info">
          <AppIcon name="info" :size="16" class="icon" />
          <span>
            该节点没有硬件画像（未通过「新增 Edge 向导」接入），下面按默认画像生成。
            在下方调整并保存后，详情页会按这台机器的实际配置复现文件。
          </span>
        </div>
        <div v-if="detailListenerWarning || detailCallbackWarning" class="alert alert-warning">
          <AppIcon name="alert" :size="16" class="icon" />
          <span>{{ detailListenerWarning || detailCallbackWarning }}</span>
        </div>
        <div class="env-head">
          <span class="mono env-hardware">{{ detailHardwareSummary }}</span>
          <span class="spacer" />
          <button class="btn btn-text btn-sm" type="button" @click="copy(detailEnv, 'edge.env')">
            <AppIcon name="copy" :size="14" />
            复制
          </button>
          <button class="btn btn-text btn-sm" type="button" @click="downloadDetailEnv">
            下载 edge.env
          </button>
        </div>
        <div class="command-box env-box">
          <pre class="mono">{{ detailEnv }}</pre>
        </div>

        <div v-if="detailPlan.warnings.length" class="alert alert-warning">
          <AppIcon name="alert" :size="16" class="icon" />
          <div class="alert-list">
            <span v-for="w in detailPlan.warnings" :key="w">{{ w }}</span>
          </div>
        </div>

        <details class="drawer-details">
          <summary>调整硬件画像（保存后写入节点）</summary>
          <div class="profile-grid">
            <label class="profile-field">
              <span>CPU 核数</span>
              <input v-model.number="detailProfile.hardware.cpuCores" class="input" type="number" min="1" max="128" />
            </label>
            <label class="profile-field">
              <span>内存（GiB）</span>
              <input v-model.number="detailProfile.hardware.memoryGb" class="input" type="number" min="1" max="512" />
            </label>
            <label class="profile-field">
              <span>缓存磁盘（GiB）</span>
              <input v-model.number="detailProfile.hardware.diskGb" class="input" type="number" min="0" max="100000" />
            </label>
            <label class="profile-field">
              <span>磁盘类型</span>
              <select
                class="select"
                :value="detailProfile.hardware.diskType"
                @change="setDetailDiskType(($event.target as HTMLSelectElement).value)"
              >
                <option value="nvme">NVMe SSD</option>
                <option value="sata-ssd">SATA SSD</option>
                <option value="hdd">机械盘 HDD</option>
              </select>
            </label>
            <label class="profile-field">
              <span>出口带宽（Mbps）</span>
              <input v-model.number="detailProfile.hardware.bandwidthMbps" class="input" type="number" min="0" max="100000" />
            </label>
            <label class="profile-field">
              <span>业务类型</span>
              <select
                class="select"
                :value="detailProfile.hardware.workload"
                @change="setDetailWorkload(($event.target as HTMLSelectElement).value)"
              >
                <option value="web">网页 / 小文件</option>
                <option value="mixed">混合业务</option>
                <option value="video">视频 / 大文件点播</option>
              </select>
            </label>
            <label class="profile-field">
              <span>节点角色</span>
              <select
                class="select"
                :value="detailProfile.hardware.role"
                @change="setDetailRole(($event.target as HTMLSelectElement).value)"
              >
                <option value="edge">普通边缘节点</option>
                <option value="shield">Origin Shield</option>
              </select>
            </label>
            <label class="profile-field span-2 checkbox">
              <input v-model="detailProfile.hardware.sharedRedis" type="checkbox" />
              <span>使用共享 Redis（区域实例即可）</span>
            </label>
            <label class="profile-field span-2 checkbox">
              <input v-model="detailProfile.infra.httpsEnabled" type="checkbox" />
              <span>启用 HTTPS 监听</span>
            </label>
            <label class="profile-field">
              <span>HTTP 监听（EDGE_LISTEN）</span>
              <input v-model="detailProfile.infra.httpListen" class="input mono" placeholder="0.0.0.0:80" />
            </label>
            <label class="profile-field">
              <span>HTTPS 监听</span>
              <input
                v-model="detailProfile.infra.httpsListen"
                class="input mono"
                :disabled="!detailProfile.infra.httpsEnabled"
                placeholder="0.0.0.0:443"
              />
            </label>
            <label class="profile-field">
              <span>管理面监听（EDGE_ADMIN_LISTEN）</span>
              <input v-model="detailProfile.infra.adminListen" class="input mono" placeholder="0.0.0.0:8081" />
            </label>
            <label class="profile-field span-2">
              <span>AGENT_URL（控制面回调）</span>
              <input
                v-model="detailProfile.infra.agentUrl"
                class="input mono"
                :placeholder="detail.node?.agent_url || 'http://<控制面可达地址>:8081'"
              />
              <em class="profile-note">
                必须指向管理面端口且控制面可达；与 EDGE_ADMIN_LISTEN 端口不一致会让 purge / 证书 / ACME 回调失败。
              </em>
            </label>
            <label class="profile-field">
              <span>CACHE_BACKEND</span>
              <select
                class="select"
                :value="detailProfile.infra.cacheBackend"
                @change="setDetailCacheBackend(($event.target as HTMLSelectElement).value)"
              >
                <option v-for="(label, value) in CACHE_BACKEND_LABEL" :key="value" :value="value">
                  {{ label }}
                </option>
              </select>
            </label>
            <label class="profile-field">
              <span>REDIS_URL</span>
              <input
                v-model="detailProfile.infra.redisUrl"
                class="input mono"
                placeholder="redis://127.0.0.1:6379/0"
              />
            </label>
            <label class="profile-field span-2">
              <span>CACHE_REDIS_URL（留空复用 REDIS_URL）</span>
              <input
                v-model="detailProfile.infra.cacheRedisUrl"
                class="input mono"
                placeholder="redis://127.0.0.1:6379/1"
              />
              <em class="profile-note">仅 CACHE_BACKEND=redis 时启用；含密码的地址会随画像存储。</em>
            </label>
            <label class="profile-field">
              <span>CHALLENGE_SECRET</span>
              <input
                v-model="detailProfile.infra.challengeSecret"
                class="input mono"
                type="password"
                autocomplete="off"
                placeholder="各节点必须一致"
              />
            </label>
            <label class="profile-field">
              <span>WAF_RULEPACK_SECRET</span>
              <input
                v-model="detailProfile.infra.wafRulepackSecret"
                class="input mono"
                type="password"
                autocomplete="off"
                placeholder="与控制面一致"
              />
            </label>
            <em class="profile-note span-2">
              两个密钥都会随硬件画像存储在控制面，仅管理员可读取；留空则文件里保留注释占位。
            </em>
          </div>
          <div class="flex-between profile-actions">
            <span class="text-muted" style="font-size: 12px">
              Sizing: {{ humanBytes(detailPlan.metrics.memoryCacheBytes) }} 内存缓存
              <template v-if="detailPlan.metrics.largeCacheEnabled">
                · {{ humanBytes(detailPlan.metrics.largeCacheBytes) }} 大对象缓存
              </template>
            </span>
            <button class="btn btn-default btn-sm" type="button" :disabled="savingProfile" @click="saveDetailProfile">
              {{ savingProfile ? '保存中…' : '保存画像' }}
            </button>
          </div>
        </details>
      </div>
    </BaseDrawer>
    <!-- 调度测试 -->
    <BaseModal v-model="schedOpen" title="调度测试" width="720px" hide-footer>
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">域名（可选）</label>
            <input v-model="schedForm.domain" class="input" placeholder="cdn.example.com" />
          </div>
          <div class="field">
            <label class="field-label">客户端 IP</label>
            <input v-model="schedForm.ip" class="input" placeholder="例如 203.0.113.9" />
            <span class="field-hint">用于匹配 GEOIP_JSON_PATH 的 CIDR 表。</span>
          </div>
          <div class="field">
            <label class="field-label">省份覆盖</label>
            <input v-model="schedForm.province" class="input" placeholder="例如 广东" />
          </div>
          <div class="field">
            <label class="field-label">运营商覆盖</label>
            <input v-model="schedForm.isp" class="input" placeholder="电信 / 联通 / 移动" />
          </div>
          <div class="field">
            <label class="field-label">城市覆盖</label>
            <input v-model="schedForm.city" class="input" placeholder="可选" />
          </div>
        </div>

        <div class="flex-between">
          <span class="text-muted" style="font-size: 12px">
            仅在线且填写了公网 IP 的节点参与调度；省份/运营商覆盖优先于 IP 解析。
          </span>
          <button class="btn btn-primary" type="button" :disabled="schedLoading" @click="runSchedule">
            {{ schedLoading ? '测试中…' : '开始测试' }}
          </button>
        </div>

        <template v-if="schedResult">
          <div class="alert alert-info" style="margin-top: 4px">
            <AppIcon name="info" :size="16" class="icon" />
            <span>
              客户端：{{ [schedResult.client.country, schedResult.client.province, schedResult.client.city, schedResult.client.isp].filter(Boolean).join(' · ') || '未知位置' }}
              · TTL {{ schedResult.ttl }}s · {{ schedResult.note }}
            </span>
          </div>
          <div class="sched-pick">
            <div class="sched-card primary">
              <div class="sched-label">主节点</div>
              <div class="sched-name">{{ schedResult.primary?.name || '无可用节点' }}</div>
              <div class="mono">{{ schedResult.primary?.public_ip || '—' }}</div>
              <div class="cell-sub">
                {{ [schedResult.primary?.country, schedResult.primary?.province, schedResult.primary?.city, schedResult.primary?.isp].filter(Boolean).join(' · ') || '未设置线路' }}
              </div>
            </div>
            <div class="sched-card">
              <div class="sched-label">备用节点</div>
              <div class="sched-name">{{ schedResult.backup?.name || '无' }}</div>
              <div class="mono">{{ schedResult.backup?.public_ip || '—' }}</div>
              <div class="cell-sub">
                {{ [schedResult.backup?.country, schedResult.backup?.province, schedResult.backup?.city, schedResult.backup?.isp].filter(Boolean).join(' · ') || '—' }}
              </div>
            </div>
          </div>

          <div class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>候选节点</th>
                  <th>国家 / 省 / 市 / 运营商</th>
                  <th class="num">权重</th>
                  <th class="num">得分</th>
                  <th>原因</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="c in schedResult.candidates" :key="c.name">
                  <td class="mono">{{ c.name }}</td>
                  <td>{{ [c.country, c.province, c.city, c.isp].filter(Boolean).join(' · ') || '—' }}</td>
                  <td class="num">{{ c.weight }}</td>
                  <td class="num">{{ c.score }}</td>
                  <td class="text-2" style="font-size: 12px">{{ c.reason }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div class="flex-between">
            <span />
            <button class="btn btn-default" type="button" @click="schedOpen = false">关闭</button>
          </div>
        </template>
      </div>
    </BaseModal>
    <!-- DNS 测试 -->
    <BaseModal v-model="dnsOpen" title="DNS 解析测试" width="620px" hide-footer>
      <div class="form-col">
        <div class="form-grid">
          <div class="field span-2">
            <label class="field-label">查询名称</label>
            <input v-model="dnsForm.name" class="input" placeholder="cname.lagranedge.com" />
          </div>
          <div class="field span-2">
            <label class="field-label">客户端 IP / 子网（可选，作为 ECS）</label>
            <input v-model="dnsForm.ip" class="input" placeholder="203.0.113.9/24" />
            <span class="field-hint">控制面用 DNS_TEST_SERVER 指定的权威 DNS 发起真实查询。</span>
          </div>
        </div>
        <div class="flex-between">
          <span class="text-muted" style="font-size: 12px">
            返回 rcode / IP / TTL；DNS 未配置或超时会显示错误。
          </span>
          <button class="btn btn-primary" type="button" :disabled="dnsLoading" @click="runDnsTest">
            {{ dnsLoading ? '查询中…' : '查询' }}
          </button>
        </div>

        <template v-if="dnsResult">
          <div class="alert alert-info">
            <AppIcon name="info" :size="16" class="icon" />
            <span>
              {{ dnsResult.server }} · rcode={{ dnsResult.rcode }} ·
              {{ dnsResult.elapsed_ms }}ms{{ dnsResult.truncated ? ' · TC' : '' }}
            </span>
          </div>
          <div v-if="dnsResult.answers.length" class="table-wrap">
            <table class="table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th class="num">TTL</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="a in dnsResult.answers" :key="a.ip">
                  <td class="mono">{{ a.ip }}</td>
                  <td class="num">{{ a.ttl }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div v-else class="text-muted" style="font-size: 13px">
            没有 A 记录（rcode={{ dnsResult.rcode }}）。
          </div>
          <div class="flex-between">
            <span />
            <button class="btn btn-default" type="button" @click="dnsOpen = false">关闭</button>
          </div>
        </template>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { copyText } from '~/utils/clipboard'
import { friendlyErrorMessage } from '~/utils/friendlyError'
import {
  CACHE_BACKEND_LABEL,
  EDGE_PROFILE_DEFAULTS,
  humanBytes,
  isValidListen,
  isValidSocketAddr,
  parseEdgeProfile,
  recommendEdgeConfig,
  renderEdgeEnvFile,
  serializeEdgeProfile,
  splitListen,
  summarizeHardware,
  type EdgeCacheBackend,
  type EdgeDiskType,
  type EdgeNodeRole,
  type EdgeProfile,
  type EdgeWorkload,
} from '~/utils/edgeSizing'

const api = useApi()
const toast = useToast()
const { ask } = useConfirm()

/** Shape returned by GET /api/v1/nodes/:id. */
interface NodeDetail {
  node: any
  token: string
  /** Server-resolved control-plane base URL (CONTROL_PUBLIC_URL / Host). */
  control_url?: string
}

const nodes = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const upgradingId = ref('')
const autoRefresh = ref(true)
const lastUpdated = ref('')

const formOpen = ref(false)
const editing = ref<any>(null)
const formError = ref('')
const form = ref({
  name: '',
  region: '',
  agent_url: '',
  public_ip: '',
  country: 'CN',
  province: '',
  city: '',
  isp: '',
  weight: 100,
})

const schedOpen = ref(false)
const schedLoading = ref(false)
const schedResult = ref<any>(null)
const schedForm = ref({ domain: '', ip: '', province: '', isp: '', city: '' })

const dnsOpen = ref(false)
const dnsLoading = ref(false)
const dnsResult = ref<any>(null)
const dnsForm = ref({ name: 'cname.lagranedge.com', ip: '' })

const detailOpen = ref(false)
const detail = ref<NodeDetail | null>(null)

// The wizard stores its hardware profile on the node, so the drawer can rebuild
// the same edge.env. Nodes registered without one fall back to the defaults and
// can be filled in here.
const detailProfile = ref<EdgeProfile>(cloneProfile(EDGE_PROFILE_DEFAULTS))
const detailProfileStored = ref(false)
const savingProfile = ref(false)

/**
 * Deep copy of the default profile.
 *
 * `structuredClone` would do, but a typed factory keeps the copy in sync with
 * the interface if a field is ever added, and it avoids relying on a global that
 * is not available in every embedded webview the console is opened in.
 */
function cloneProfile(profile: EdgeProfile): EdgeProfile {
  return {
    hardware: { ...profile.hardware },
    infra: { ...profile.infra },
  }
}

/** `<select>` yields a plain string; narrow it back to the union it belongs to. */
function setDetailDiskType(value: string) {
  detailProfile.value.hardware.diskType = value as EdgeDiskType
}

function setDetailWorkload(value: string) {
  detailProfile.value.hardware.workload = value as EdgeWorkload
}

function setDetailRole(value: string) {
  detailProfile.value.hardware.role = value as EdgeNodeRole
}

function setDetailCacheBackend(value: string) {
  detailProfile.value.infra.cacheBackend = value as EdgeCacheBackend
}

const detailPlan = computed(() =>
  recommendEdgeConfig(detailProfile.value.hardware, {
    cacheBackend: detailProfile.value.infra.cacheBackend,
    redisConfigured: Boolean(
      detailProfile.value.infra.redisUrl.trim() || detailProfile.value.infra.cacheRedisUrl.trim(),
    ),
  }),
)
const detailHardwareSummary = computed(() => summarizeHardware(detailProfile.value.hardware))

/**
 * The control plane calls `AGENT_URL`; the edge binds `EDGE_ADMIN_LISTEN`.
 * A port mismatch keeps heartbeats green while purge/cert/ACME fail, so it is
 * surfaced before the operator copies the file.
 */
const detailListenerWarning = computed(() => {
  if (!isValidSocketAddr(detailProfile.value.infra.adminListen.trim())) {
    return 'EDGE_ADMIN_LISTEN 必须是 IP:端口（不能写主机名），例如 0.0.0.0:8081。'
  }
  if (!isValidListen(detailProfile.value.infra.httpListen.trim())) {
    return 'EDGE_LISTEN 格式应为 IP/主机:端口，例如 0.0.0.0:80。'
  }
  if (
    detailProfile.value.infra.httpsEnabled &&
    !isValidListen(detailProfile.value.infra.httpsListen.trim())
  ) {
    return 'HTTPS 监听地址格式应为 IP/主机:端口，例如 0.0.0.0:443。'
  }
  return ''
})

const detailCallbackWarning = computed(() => {
  const agent = detailProfile.value.infra.agentUrl.trim()
  const admin = splitListen(detailProfile.value.infra.adminListen)
  if (!agent || !admin) return ''
  try {
    const url = new URL(agent)
    const port = url.port || (url.protocol === 'https:' ? '443' : '80')
    const agentHost = url.hostname.replace(/^\[/, '').replace(/\]$/, '').toLowerCase()
    const adminHost = admin.host.replace(/^\[/, '').replace(/\]$/, '').toLowerCase()
    const loopback = (host: string) =>
      host === 'localhost' || host === '::1' || host.startsWith('127.')
    if (port !== admin.port) {
      return `AGENT_URL 端口 ${port} 与 EDGE_ADMIN_LISTEN 端口 ${admin.port} 不一致，purge / 证书 / ACME 回调会失败。`
    }
    if (loopback(adminHost) && !loopback(agentHost)) {
      return '管理面只监听回环地址，但 AGENT_URL 使用非回环地址，控制面无法回调。'
    }
    if (!loopback(adminHost) && loopback(agentHost)) {
      return 'AGENT_URL 指向回环地址，跨机控制面无法回调。'
    }
  } catch {
    return 'AGENT_URL 不是合法的 http(s) 地址。'
  }
  return ''
})

const detailEnv = computed(() => {
  if (!detail.value) return ''
  const node = detail.value.node || {}
  return renderEdgeEnvFile({
    nodeId: node.name || '',
    region: node.region || '',
    publicIp: node.public_ip || '',
    // Prefer the stored profile (the wizard derives it from EDGE_ADMIN_LISTEN);
    // fall back to the value the node reported on its heartbeat.
    agentUrl:
      detailProfile.value.infra.agentUrl.trim() ||
      node.agent_url ||
      (node.public_ip ? `http://${node.public_ip}:8081` : ''),
    token: detail.value.token || '',
    // The API resolves CONTROL_PUBLIC_URL / the request Host; the browser
    // origin is only a fallback for older control planes.
    controlUrl:
      detail.value.control_url || (import.meta.client ? window.location.origin : ''),
    httpListen: detailProfile.value.infra.httpListen,
    adminListen: detailProfile.value.infra.adminListen,
    httpsEnabled: detailProfile.value.infra.httpsEnabled,
    httpsListen: detailProfile.value.infra.httpsListen,
    // Every value that changes the file comes from the profile so the drawer
    // matches the wizard; only AGENT_TOKEN comes from the node record.
    redisUrl: detailProfile.value.infra.redisUrl,
    cacheRedisUrl: detailProfile.value.infra.cacheRedisUrl,
    challengeSecret: detailProfile.value.infra.challengeSecret,
    wafRulepackSecret: detailProfile.value.infra.wafRulepackSecret,
    hardware: detailProfile.value.hardware,
    plan: detailPlan.value,
  })
})

let timer: ReturnType<typeof setInterval> | null = null

const page = ref(1)
const pageSize = 10
const pagedNodes = computed(() => {
  const start = (page.value - 1) * pageSize
  return nodes.value.slice(start, start + pageSize)
})

function exportNodes() {
  exportCsv(`lagran-nodes-${new Date().toISOString().slice(0, 10)}`, nodes.value, [
    { key: 'name', label: '节点' },
    { key: 'region', label: '区域' },
    { key: 'status', label: '状态' },
    { key: 'version', label: '版本' },
    { key: 'public_ip', label: '公网 IP' },
    { key: 'agent_url', label: 'Agent 地址' },
    { key: 'cpu_usage', label: 'CPU%' },
    { key: 'memory_usage', label: '内存%' },
    { key: 'last_heartbeat', label: '最后心跳' },
  ])
}
watch(
  () => nodes.value.length,
  (total) => {
    const last = Math.max(1, Math.ceil(total / pageSize))
    if (page.value > last) page.value = last
  },
)

const counts = computed(() => {
  const result = { online: 0, offline: 0, pending: 0, disabled: 0 }
  for (const n of nodes.value) {
    if (n.status === 'online') result.online += 1
    else if (n.status === 'pending') result.pending += 1
    else if (n.status === 'disabled') result.disabled += 1
    else result.offline += 1
  }
  return result
})

function statusLabel(status: string) {
  return (
    {
      online: '在线',
      offline: '离线',
      pending: '待接入',
      disabled: '已停用',
    } as Record<string, string>
  )[status] || status
}

function statusTone(status: string) {
  if (status === 'online') return 'success'
  if (status === 'pending') return 'warning'
  if (status === 'disabled') return 'danger'
  return 'neutral'
}

function usageColor(value?: number | null) {
  if (value == null) return 'var(--brand)'
  if (value >= 85) return 'var(--danger)'
  if (value >= 70) return 'var(--warning)'
  return 'var(--brand)'
}

async function load() {
  loading.value = true
  try {
    nodes.value = (await api.get<any[]>('/api/v1/nodes')) || []
    lastUpdated.value = new Date().toLocaleTimeString('zh-CN', { hour12: false })
  } catch (e: any) {
    // Non-admin or control-plane error: keep the previous list.
  } finally {
    loading.value = false
  }
}

function openEdit(node: any) {
  editing.value = node
  formError.value = ''
  form.value = {
    name: node.name,
    region: node.region || '',
    agent_url: node.agent_url || '',
    public_ip: node.public_ip || '',
    country: node.country || 'CN',
    province: node.province || '',
    city: node.city || '',
    isp: node.isp || '',
    weight: node.weight ?? 100,
  }
  formOpen.value = true
}

function openSchedule() {
  schedResult.value = null
  schedForm.value = { domain: '', ip: '', province: '', isp: '', city: '' }
  schedOpen.value = true
}

async function runSchedule() {
  schedLoading.value = true
  try {
    schedResult.value = await api.post('/api/v1/schedule/test', {
      domain: schedForm.value.domain.trim(),
      ip: schedForm.value.ip.trim(),
      province: schedForm.value.province.trim(),
      isp: schedForm.value.isp.trim(),
      city: schedForm.value.city.trim(),
    })
  } catch (e: any) {
    toast.error(e?.data?.error || '调度测试失败')
  } finally {
    schedLoading.value = false
  }
}

function openDnsTest() {
  dnsResult.value = null
  dnsOpen.value = true
}

async function runDnsTest() {
  if (!dnsForm.value.name.trim()) {
    toast.error('请填写查询名称')
    return
  }
  dnsLoading.value = true
  try {
    dnsResult.value = await api.post('/api/v1/dns/test', {
      name: dnsForm.value.name.trim(),
      ip: dnsForm.value.ip.trim(),
    })
  } catch (e: any) {
    toast.error(e?.data?.error || 'DNS 查询失败')
  } finally {
    dnsLoading.value = false
  }
}

async function submitForm() {
  formError.value = ''
  if (!form.value.name.trim()) {
    formError.value = '请填写节点名称'
    return
  }
  saving.value = true
  try {
    const payload = {
      region: form.value.region.trim(),
      // AGENT_URL is managed next to EDGE_ADMIN_LISTEN in the detail drawer;
      // editing it here alone would silently disagree with the stored profile.
      public_ip: form.value.public_ip.trim(),
      country: form.value.country.trim().toUpperCase() || 'CN',
      province: form.value.province.trim(),
      city: form.value.city.trim(),
      isp: form.value.isp.trim(),
      weight: Number(form.value.weight) || 100,
    }
    if (!editing.value) return
    await api.put(`/api/v1/nodes/${editing.value.id}`, payload)
    formOpen.value = false
    toast.success('节点信息已更新')
    await load()
  } catch (e: any) {
    const message = friendlyErrorMessage(e?.data?.error, '保存失败，请稍后重试')
    formError.value = message
    toast.error(message)
  } finally {
    saving.value = false
  }
}

async function openDetail(node: any) {
  detail.value = null
  detailOpen.value = true
  try {
    const res = await api.get<NodeDetail>(`/api/v1/nodes/${node.id}`)
    detail.value = res
    // Parse the stored profile defensively; anything unreadable falls back to
    // the defaults instead of breaking the drawer.
    const stored = parseEdgeProfile((res.node as any)?.edge_profile)
    detailProfile.value = stored ?? cloneProfile(EDGE_PROFILE_DEFAULTS)
    detailProfileStored.value = stored !== null
    // Profiles written before `agentUrl` was stored fall back to the value the
    // node already reported, so saving the drawer does not blank the callback.
    if (!detailProfile.value.infra.agentUrl) {
      detailProfile.value.infra.agentUrl = (res.node as any)?.agent_url || ''
    }
  } catch (e: any) {
    detailOpen.value = false
    toast.error(e?.data?.error || '读取节点详情失败')
  }
}

/** Persist the drawer's hardware edits so the file survives a page reload. */
async function saveDetailProfile() {
  const node = detail.value?.node
  if (!node?.id) return
  const problem = detailListenerWarning.value || detailCallbackWarning.value
  if (problem) {
    toast.error(problem)
    return
  }
  savingProfile.value = true
  try {
    await api.put(`/api/v1/nodes/${node.id}`, {
      // Keep the node's callback URL in agreement with the profile; otherwise
      // the control plane keeps calling an address the edge no longer binds.
      agent_url: detailProfile.value.infra.agentUrl.trim(),
      max_bandwidth_mbps: Math.round(Number(detailProfile.value.hardware.bandwidthMbps) || 0),
      edge_profile: serializeEdgeProfile(detailProfile.value),
    })
    detailProfileStored.value = true
    toast.success('硬件画像已保存，配置已按新画像重算')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '保存硬件画像失败')
  } finally {
    savingProfile.value = false
  }
}

function downloadDetailEnv() {
  if (!import.meta.client || !detailEnv.value) return
  const name = detail.value?.node?.name || 'edge'
  const blob = new Blob([detailEnv.value], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `edge-${name}.env`
  a.click()
  URL.revokeObjectURL(url)
}

async function upgrade(node: any) {
  if (!node.agent_url || !node.has_token) {
    toast.error('该节点缺少 Agent 地址或令牌，无法远程升级')
    return
  }
  const ok = await ask({
    title: '升级边缘节点',
    message: `将让 ${node.name} 从控制面获取最新 Release，下载校验后自动替换二进制并重启。升级期间该节点流量会短暂中断。确认继续？`,
    confirmText: '开始升级',
  })
  if (!ok) return
  upgradingId.value = node.id
  let queued = false
  try {
    const result = await api.post<any>(`/api/v1/nodes/${node.id}/upgrade`, {})
    queued = true
    toast.success(`升级任务已下发：${result.version}，节点将在下载校验后自动重启`)
    window.setTimeout(load, 5000)
    window.setTimeout(load, 15000)
  } catch (e: any) {
    toast.error(friendlyErrorMessage(e?.data?.error, '升级任务下发失败'))
  } finally {
    if (!queued) {
      upgradingId.value = ''
    } else {
      window.setTimeout(() => {
        if (upgradingId.value === node.id) upgradingId.value = ''
      }, 20000)
    }
  }
}

async function toggle(node: any) {
  const enable = node.status === 'disabled'
  if (!enable) {
    const ok = await ask({
      title: '停用节点',
      message: `停用后 ${node.name} 将立即返回 503，不再代理任何流量；心跳和健康检查仍然保留。确认停用？`,
      confirmText: '停用',
      danger: true,
    })
    if (!ok) return
  }
  try {
    await api.post(`/api/v1/nodes/${node.id}/status`, { enabled: enable })
    toast.success(enable ? '节点已启用，等待下一次心跳' : '节点已停用，边缘将在下一次心跳后停止代理')
    await load()
    if (detailOpen.value && detail.value?.node.id === node.id) {
      detail.value = await api.get<NodeDetail>(`/api/v1/nodes/${node.id}`).catch(() => detail.value)
    }
  } catch (e: any) {
    toast.error(e?.data?.error || '状态更新失败')
  }
}

async function remove(node: any) {
  const ok = await ask({
    title: '删除节点',
    message: `删除 ${node.name} 后会吊销其令牌并停止下发刷新/证书。如果该节点仍在运行，下次心跳会自动重新注册。`,
    confirmText: '删除',
    danger: true,
  })
  if (!ok) return
  try {
    await api.del(`/api/v1/nodes/${node.id}`)
    toast.success('节点已删除')
    await load()
  } catch (e: any) {
    toast.error(e?.data?.error || '删除失败')
  }
}

async function copy(text: string, label: string) {
  if (await copyText(text)) {
    toast.success(`${label}已复制`)
  } else {
    toast.error('复制失败，请手动选择文本')
  }
}

watch(autoRefresh, (on) => {
  if (timer) {
    clearInterval(timer)
    timer = null
  }
  if (on) timer = setInterval(load, 10000)
})

onMounted(() => {
  load()
  if (autoRefresh.value) timer = setInterval(load, 10000)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
.resource {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 2px 0;
}

.res-label {
  width: 30px;
  font-size: 11px;
  color: var(--text-3);
}

.res-bar {
  flex: 1;
  min-width: 60px;
}

.res-val {
  width: 30px;
  text-align: right;
  font-size: 11px;
  color: var(--text-3);
  font-variant-numeric: tabular-nums;
}

.copy-row {
  display: flex;
  gap: 8px;
}

.copy-row .input {
  flex: 1;
  font-size: 13px;
}

/* edge.env view in the node drawer: the file is long, so it scrolls inside a
   fixed-height box instead of stretching the drawer. */
.env-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}

.env-hardware {
  font-size: 11.5px;
  color: var(--text-3);
}

.command-box.env-box {
  max-height: 360px;
  overflow: auto;
}

.drawer-details {
  padding: 10px 12px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
}

.drawer-details summary {
  cursor: pointer;
  font-size: 12.5px;
  color: var(--text-2);
  user-select: none;
}

.drawer-details[open] summary {
  margin-bottom: 10px;
}

.profile-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px 10px;
}

.profile-field {
  display: flex;
  flex-direction: column;
  gap: 3px;
  min-width: 0;
  font-size: 11.5px;
  color: var(--text-3);
}

.profile-field .input,
.profile-field .select {
  height: 32px;
}

.profile-field.span-2 {
  grid-column: span 2;
}

.profile-field.checkbox {
  flex-direction: row;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  color: var(--text-2);
}

.profile-note {
  font-style: normal;
  font-size: 11px;
  color: var(--text-3);
  line-height: 1.4;
}

.profile-actions {
  margin-top: 10px;
}

.command-box {
  position: relative;
  background: #0f172a;
  border-radius: var(--radius);
  padding: 14px 16px;
  overflow-x: auto;
}

.command-box pre {
  margin: 0;
  color: #d6e8ff;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px 18px;
}

.sched-pick {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.sched-card {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: #fafbfc;
}

.sched-card.primary {
  border-color: #bedaff;
  background: var(--brand-bg);
}

.sched-label {
  font-size: 11.5px;
  color: var(--text-3);
}

.sched-name {
  margin-top: 4px;
  font-size: 14px;
  font-weight: 500;
  color: var(--text);
}

.detail-item.span-2 {
  grid-column: span 2;
}

.detail-label {
  font-size: 12px;
  color: var(--text-3);
}

.detail-value {
  margin-top: 3px;
  font-size: 13.5px;
  color: var(--text);
  word-break: break-all;
}

.section-title {
  margin-top: 4px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--divider);
  font-size: 13px;
  font-weight: 500;
  color: var(--text-2);
}

@media (max-width: 640px) {
  .detail-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .detail-item.span-2 {
    grid-column: span 1;
  }

  .table {
    min-width: 900px;
  }
}
</style>
