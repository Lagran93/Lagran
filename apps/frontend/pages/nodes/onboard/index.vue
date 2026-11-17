<template>
  <div class="page">
    <div class="page-head">
      <div>
        <div class="page-title">新增 Edge 节点</div>
        <div class="page-desc">
          按节点硬件与业务类型推导容量参数，生成可直接落地的 edge.env；节点注册与控制台预注册一步完成
        </div>
      </div>
      <NuxtLink to="/nodes" class="btn btn-default">
        <AppIcon name="chevron-left" :size="15" />
        返回节点列表
      </NuxtLink>
    </div>

    <div v-if="!auth.isAdmin" class="alert alert-warning">
      <AppIcon name="alert" :size="16" class="icon" />
      <span>只有管理员可以添加边缘节点。当前账号可以查看节点列表，但不能注册新节点。</span>
    </div>

    <template v-else>
      <div class="wizard-steps">
        <div
          v-for="(s, i) in steps"
          :key="s"
          class="wizard-step"
          :class="{ active: step === i, done: step > i }"
        >
          <span class="wizard-index">{{ step > i ? '✓' : i + 1 }}</span>
          <span>{{ s }}</span>
        </div>
      </div>

      <div v-if="nodeLocked" class="alert alert-info">
        <AppIcon name="info" :size="16" class="icon" />
        <span>
          节点 <b>{{ created?.node?.name }}</b> 已在控制台注册，身份与硬件信息已锁定；
          修改容量参数只会重新生成 edge.env，不会再次注册。需要改名请删除该节点后重新接入。
        </span>
      </div>

      <div class="card">
        <div class="card-body">
          <!-- 步骤 1：节点身份 -->
          <div v-if="step === 0" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon"><AppIcon name="node" :size="24" /></div>
              <div>
                <div class="wizard-title">这个节点叫什么、放在哪里？</div>
                <div class="wizard-desc">
                  名称是节点在控制台与心跳中的唯一标识，必须与边缘端的 NODE_ID 完全一致。
                </div>
              </div>
            </div>
            <div class="form-grid">
              <div class="field span-2">
                <label class="field-label">节点名称 <span class="req">*</span></label>
                <input
                  v-model="form.name"
                  class="input mono"
                  placeholder="edge-hk-01"
                  :disabled="nodeLocked"
                  @keyup.enter="next"
                />
                <span class="field-hint">
                  仅允许字母、数字、点、下划线与连字符，最长 64 字符；它会原样写入 edge.env 的 NODE_ID。
                </span>
              </div>
              <div class="field">
                <label class="field-label">区域标签</label>
                <input
                  v-model="form.region"
                  class="input multi"
                  placeholder="cn-hongkong"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">只用字母 / 数字 / . / _ / -，用于展示与排障分组。</span>
              </div>
              <div class="field">
                <label class="field-label">公网 IP <span class="req">*</span></label>
                <input
                  v-model="form.public_ip"
                  class="input multi"
                  placeholder="203.0.113.21"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">GeoDNS 返回这个地址，必须是对访客可达的 IP。</span>
              </div>
              <div class="field span-2">
                <label class="field-label">Agent 地址</label>
                <input
                  v-model="form.agent_url"
                  class="input multi"
                  placeholder="http://203.0.113.21:8081"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">
                  控制面回调该节点的管理面地址（对应 EDGE_ADMIN_LISTEN），用于下发刷新、证书与 ACME；
                  不要填 80/443 数据端口。
                </span>
              </div>
            </div>


            <details class="optional-block">
              <summary>调度归属（可选：国家 / 省份 / 城市 / 运营商 / 权重）</summary>
              <div class="form-grid">
                <div class="field">
                  <label class="field-label">国家/地区代码</label>
                  <input
                    v-model="form.country"
                    class="input"
                    list="edge-country-codes"
                    maxlength="2"
                    placeholder="CN"
                    :disabled="nodeLocked"
                  />
                  <datalist id="edge-country-codes">
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
                  </datalist>
                </div>
                <div class="field">
                  <label class="field-label">省份</label>
                  <input
                    v-model="form.province"
                    class="input multi"
                    placeholder="广东"
                    :disabled="nodeLocked"
                  />
                </div>
                <div class="field">
                  <label class="field-label">城市</label>
                  <input
                    v-model="form.city"
                    class="input multi"
                    placeholder="深圳"
                    :disabled="nodeLocked"
                  />
                </div>
                <div class="field">
                  <label class="field-label">运营商</label>
                  <input
                    v-model="form.isp"
                    class="input multi"
                    placeholder="电信 / BGP"
                    :disabled="nodeLocked"
                  />
                </div>
                <div class="field">
                  <label class="field-label">调度权重</label>
                  <input
                    v-model.number="form.weight"
                    class="input"
                    type="number"
                    min="0"
                    max="1000"
                    :disabled="nodeLocked"
                  />
                  <span class="field-hint">数值越大越优先，默认 100。</span>
                </div>
              </div>
            </details>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>

          <!-- 步骤 2：硬件画像 -->
          <div v-else-if="step === 1" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon"><AppIcon name="zap" :size="24" /></div>
              <div>
                <div class="wizard-title">这台机器的硬件与业务画像</div>
                <div class="wizard-desc">
                  向导按 CPU 核数、内存、磁盘类型与业务类型推导缓存容量、分片大小与超时，不用手算。
                </div>
              </div>
            </div>

            <div class="form-grid">
              <div class="field">
                <label class="field-label">CPU 核数 <span class="req">*</span></label>
                <input
                  v-model.number="hw.cpuCores"
                  class="input"
                  type="number"
                  min="1"
                  max="128"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">决定工作线程数；单核会把 TLS 与回源握手串行。</span>
              </div>
              <div class="field">
                <label class="field-label">内存（GiB）<span class="req">*</span></label>
                <input
                  v-model.number="hw.memoryGb"
                  class="input"
                  type="number"
                  min="1"
                  max="512"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">内存的 25% 划给 L1 缓存，上限 8 GiB。</span>
              </div>
              <div class="field">
                <label class="field-label">缓存磁盘容量（GiB）</label>
                <input
                  v-model.number="hw.diskGb"
                  class="input"
                  type="number"
                  min="0"
                  max="100000"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">填 0 表示只做内存缓存，重启后缓存全丢。</span>
              </div>
              <div class="field">
                <label class="field-label">磁盘类型</label>
                <select
                  class="select"
                  :value="hw.diskType"
                  :disabled="nodeLocked"
                  @change="setDiskType(($event.target as HTMLSelectElement).value)"
                >
                  <option value="nvme">NVMe SSD</option>
                  <option value="sata-ssd">SATA SSD</option>
                  <option value="hdd">机械盘 HDD</option>
                </select>
                <span class="field-hint">决定分片大小与写队列：机械盘分片放大到 4 MiB。</span>
              </div>
              <div class="field">
                <label class="field-label">出口带宽（Mbps）</label>
                <input
                  v-model.number="hw.bandwidthMbps"
                  class="input"
                  type="number"
                  min="0"
                  max="100000"
                  :disabled="nodeLocked"
                />
                <span class="field-hint">用于校验核数是否够用，并影响连接复用与超时。</span>
              </div>
              <div class="field">
                <label class="field-label">主要业务类型</label>
                <select
                  class="select"
                  :value="hw.workload"
                  :disabled="nodeLocked"
                  @change="setWorkload(($event.target as HTMLSelectElement).value)"
                >
                  <option value="web">网页 / 小文件</option>
                  <option value="mixed">混合业务</option>
                  <option value="video">视频 / 大文件点播</option>
                </select>
                <span class="field-hint">决定默认 TTL、大对象缓存门槛与回源超时。</span>
              </div>
            </div>

            <div class="toggle-list">
              <label class="check">
                <input v-model="hw.sharedRedis" type="checkbox" :disabled="nodeLocked" />
                使用共享 Redis（区域实例即可，无需与控制面同一台）
              </label>
              <label class="check">
                <input v-model="infra.httpsEnabled" type="checkbox" />
                启用 HTTPS 监听（证书由控制面同步）
              </label>
            </div>
            <span class="field-hint">
              共享 Redis 勾选后才会按带宽输出 CACHE_FLIGHT_TIMEOUT_MS / CC_REDIS_TIMEOUT_MS；
              是否真正跨节点共享由下面的 REDIS_URL 与 CACHE_BACKEND 决定。
            </span>

            <div class="form-grid">
              <div class="field">
                <label class="field-label">HTTPS 监听地址</label>
                <input
                  v-model="infra.httpsListen"
                  class="input mono"
                  :disabled="!infra.httpsEnabled"
                  placeholder="0.0.0.0:443"
                />
              </div>
              <div class="field">
                <label class="field-label">CACHE_BACKEND</label>
                <select
                  class="select"
                  :value="infra.cacheBackend"
                  @change="setCacheBackend(($event.target as HTMLSelectElement).value)"
                >
                  <option v-for="(label, value) in CACHE_BACKEND_LABEL" :key="value" :value="value">
                    {{ label }}
                  </option>
                </select>
                <span class="field-hint">
                  redis 为「内存 + Redis L2」共享缓存；自动则按磁盘容量推导 memory / hybrid。
                </span>
              </div>
              <div class="field">
                <label class="field-label">REDIS_URL（共享 Redis）</label>
                <input
                  v-model="infra.redisUrl"
                  class="input mono"
                  placeholder="redis://127.0.0.1:6379/0"
                />
                <span class="field-hint">
                  CC 计数、跨节点合并锁与 L2 回退共用；留空则这些能力只在单节点进程内生效。
                </span>
              </div>
              <div class="field">
                <label class="field-label">CACHE_REDIS_URL（L2 专用，可选）</label>
                <input
                  v-model="infra.cacheRedisUrl"
                  class="input mono"
                  placeholder="留空复用 REDIS_URL"
                />
                <span class="field-hint">
                  仅 CACHE_BACKEND=redis 时启用；地址含密码时会随硬件画像一并存储。
                </span>
              </div>
              <div class="field">
                <label class="field-label">管理面监听（EDGE_ADMIN_LISTEN）</label>
                <input v-model="infra.adminListen" class="input mono" placeholder="127.0.0.1:8081" />
                <span class="field-hint">
                  控制面通过 AGENT_URL 回调这里；只监听回环时要求控制面与节点同机。
                </span>
              </div>
            </div>

            <div v-if="infraWarnings.length" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <div class="alert-list">
                <span v-for="w in infraWarnings" :key="w">{{ w }}</span>
              </div>
            </div>

            <details class="optional-block">
              <summary>共享密钥（多节点部署建议填写）</summary>
              <div class="form-grid">
                <div class="field">
                  <label class="field-label">CHALLENGE_SECRET</label>
                  <input v-model="infra.challengeSecret" class="input mono" autocomplete="off" />
                  <span class="field-hint">各节点必须一致，否则质询无法跨节点通过。</span>
                </div>
                <div class="field">
                  <label class="field-label">WAF_RULEPACK_SECRET</label>
                  <input v-model="infra.wafRulepackSecret" class="input mono" autocomplete="off" />
                  <span class="field-hint">需与控制面的值完全一致，否则规则包验签失败。</span>
                </div>
              </div>
            </details>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>


          <!-- 步骤 3：容量规划 -->
          <div v-else-if="step === 2" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon"><AppIcon name="stats" :size="24" /></div>
              <div>
                <div class="wizard-title">按硬件推导出的容量规划</div>
                <div class="wizard-desc">
                  {{ hardwareSummary }}。每条参数都标注了推导依据，可按需微调后再生成配置。
                </div>
              </div>
            </div>

            <div class="metric-grid">
              <div class="metric-card">
                <div class="metric-label">工作线程</div>
                <div class="metric-value">{{ plan.metrics.workerThreads }}</div>
                <div class="metric-sub">建议等于 CPU 核数</div>
              </div>
              <div class="metric-card">
                <div class="metric-label">L1 内存缓存</div>
                <div class="metric-value">{{ humanBytes(plan.metrics.memoryCacheBytes) }}</div>
                <div class="metric-sub">约 {{ plan.metrics.cacheCapacity.toLocaleString('zh-CN') }} 个对象</div>
              </div>
              <div class="metric-card">
                <div class="metric-label">普通磁盘缓存</div>
                <div class="metric-value">
                  {{ plan.metrics.diskCacheBytes > 0 ? humanBytes(plan.metrics.diskCacheBytes) : '—' }}
                </div>
                <div class="metric-sub">{{ plan.metrics.cacheBackend }} 后端</div>
              </div>
              <div class="metric-card">
                <div class="metric-label">大对象缓存</div>
                <div class="metric-value">
                  {{ plan.metrics.largeCacheEnabled ? humanBytes(plan.metrics.largeCacheBytes) : '已关闭' }}
                </div>
                <div class="metric-sub">
                  {{ plan.metrics.largeCacheEnabled ? `分片 ${humanBytes(plan.metrics.chunkBytes)}` : '不占用磁盘' }}
                </div>
              </div>
            </div>

            <div v-if="plan.warnings.length" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <div class="alert-list">
                <span v-for="w in plan.warnings" :key="w">{{ w }}</span>
              </div>
            </div>

            <div class="override-block">
              <div class="override-title">手工微调（留空则使用推荐值）</div>
              <div class="override-grid">
                <label class="override-field">
                  <span>工作线程</span>
                  <input
                    v-model.number="overrides.workerThreads"
                    class="input"
                    type="number"
                    min="1"
                    max="256"
                    :placeholder="String(plan.metrics.workerThreads)"
                  />
                </label>
                <label class="override-field">
                  <span>内存缓存（MiB）</span>
                  <input
                    v-model.number="overrides.memoryCacheMiB"
                    class="input"
                    type="number"
                    min="16"
                    :placeholder="String(Math.round(plan.metrics.memoryCacheBytes / 1048576))"
                  />
                </label>
                <label class="override-field">
                  <span>大对象缓存（GiB，0 = 关闭）</span>
                  <input
                    v-model.number="overrides.largeCacheGiB"
                    class="input"
                    type="number"
                    min="0"
                    :placeholder="String(Math.round(plan.metrics.largeCacheBytes / 1073741824))"
                  />
                </label>
              </div>
            </div>

            <div class="table-wrap">
              <table class="table plan-table">
                <thead>
                  <tr>
                    <th style="min-width: 210px">参数</th>
                    <th style="min-width: 130px">取值</th>
                    <th style="min-width: 260px">推导依据</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in plan.items" :key="item.key">
                    <td>
                      <span class="mono plan-key">{{ item.key }}</span>
                      <span v-if="item.overridden" class="tag-manual">手工</span>
                    </td>
                    <td class="mono plan-value">{{ displayValue(item) }}</td>
                    <td class="text-2 plan-reason">{{ item.reason }}</td>
                  </tr>
                </tbody>
              </table>
            </div>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>


          <!-- 步骤 4：生成配置 -->
          <div v-else-if="step === 3" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon"><AppIcon name="logs" :size="24" /></div>
              <div>
                <div class="wizard-title">把配置和安装命令带到节点上</div>
                <div class="wizard-desc">
                  令牌只在注册时展示一次；edge.env 已按 {{ hardwareSummary }} 生成完毕。
                </div>
              </div>
            </div>

            <div class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <span>
                令牌等同该节点的身份凭证，请通过安全通道传递；删除节点会立即吊销它。
                edge.env 内含令牌，落盘后权限必须是 600。
              </span>
            </div>

            <div class="field">
              <div class="field-label">节点令牌</div>
              <div class="copy-row">
                <input
                  class="input mono"
                  :type="tokenVisible ? 'text' : 'password'"
                  :value="created?.token || ''"
                  readonly
                />
                <button class="btn btn-default" type="button" @click="tokenVisible = !tokenVisible">
                  <AppIcon :name="tokenVisible ? 'eye-off' : 'eye'" :size="15" />
                  {{ tokenVisible ? '隐藏' : '显示' }}
                </button>
                <button class="btn btn-default" type="button" @click="copy(created?.token || '', '令牌')">
                  <AppIcon name="copy" :size="15" />
                  复制
                </button>
              </div>
            </div>

            <div class="segmented">
              <button type="button" :class="{ active: tab === 'env' }" @click="tab = 'env'">
                edge.env（推荐）
              </button>
              <button type="button" :class="{ active: tab === 'binary' }" @click="tab = 'binary'">
                一键命令 · 二进制
              </button>
              <button type="button" :class="{ active: tab === 'docker' }" @click="tab = 'docker'">
                一键命令 · Docker
              </button>
            </div>

            <div class="command-box">
              <pre class="mono">{{ activeContent }}</pre>
              <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(activeContent, tabLabel)">
                <AppIcon name="copy" :size="14" />
                复制
              </button>
            </div>

            <div v-if="tab === 'env'" class="flex-between">
              <span class="text-muted" style="font-size: 12px">
                {{ envText.split('\n').length }} 行 · 含硬件推导注释
              </span>
              <button class="btn btn-default btn-sm" type="button" @click="downloadEnv">
                下载 edge.env
              </button>
            </div>

            <div class="tips">
              <div class="tip-row">
                <span class="tip-index">1</span>
                <span>把 edge.env 与 lagran-edge 二进制一起上传到节点，配置放到 /etc/lagran/edge.env。</span>
              </div>
              <div class="tip-row">
                <span class="tip-index">2</span>
                <span>确认节点能访问控制面 {{ controlUrl }}，且 EDGE_LISTEN 端口对访客开放。</span>
              </div>
              <div class="tip-row">
                <span class="tip-index">3</span>
                <span>启动后约 15 秒完成首次心跳；下一步会实时等待它上线。</span>
              </div>
            </div>

            <div class="command-box sub">
              <pre class="mono">{{ installSteps }}</pre>
              <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(installSteps, '应用命令')">
                <AppIcon name="copy" :size="14" />
                复制
              </button>
            </div>
          </div>


          <!-- 步骤 5：上线验证 -->
          <div v-else class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon"><AppIcon name="activity" :size="24" /></div>
              <div>
                <div class="wizard-title">等待节点首次心跳</div>
                <div class="wizard-desc">
                  控制台每 3 秒查询一次；节点启动后约 15 秒应变为「在线」，60 秒无心跳会记为离线。
                </div>
              </div>
            </div>

            <div class="status-panel" :class="liveTone">
              <div class="status-main">
                <StatusTag :tone="liveStatusObject.tone" dot>
                  {{ liveStatusObject.label }}
                </StatusTag>
                <span class="mono status-name">{{ form.name }}</span>
              </div>
              <div class="status-meta">
                <span>{{ form.public_ip || '未填公网 IP' }}</span>
                <span v-if="liveNode?.version">版本 {{ liveNode.version }}</span>
                <span v-if="liveNode?.last_heartbeat">最后心跳 {{ fromNow(liveNode.last_heartbeat) }}</span>
                <span v-else>尚未收到心跳</span>
              </div>
            </div>

            <div class="tips">
              <div class="tip-row">
                <span class="tip-index">1</span>
                <span v-if="isLive">
                  节点已上线，可以开始为域名配置解析；接下来可在节点列表查看资源曲线。
                </span>
                <span v-else>
                  若长时间停留「待接入」：检查 AGENT_TOKEN 与 NODE_ID 是否与 edge.env 一致、
                  节点到 {{ controlUrl }} 的网络是否可达，以及 /var/log 中 lagran-edge 的启动日志。
                </span>
              </div>
              <div class="tip-row">
                <span class="tip-index">2</span>
                <span>
                  修改配置后需要重启服务；本向导生成的 edge.env 可随时在节点详情里通过
                  「安装命令」重新获取。
                </span>
              </div>
            </div>

            <div class="flex-between">
              <span class="text-muted" style="font-size: 12px">
                {{ polling ? '正在检测…' : '检测已暂停' }}
              </span>
              <button class="btn btn-default btn-sm" type="button" @click="pollOnce">
                <AppIcon name="refresh" :size="14" />
                立即检测
              </button>
            </div>
          </div>
        </div>

        <div class="wizard-foot">
          <button
            v-if="step > 0 && step < 3"
            class="btn btn-default"
            type="button"
            @click="prev"
          >
            <AppIcon name="chevron-left" :size="15" />
            上一步
          </button>
          <span class="spacer" />
          <span class="text-muted foot-hint">{{ footHint }}</span>
          <button
            v-if="step === 0 || step === 1"
            class="btn btn-primary"
            type="button"
            @click="next"
          >
            下一步
            <AppIcon name="chevron-right" :size="15" />
          </button>
          <button
            v-else-if="step === 2"
            class="btn btn-primary"
            type="button"
            :disabled="creating"
            @click="next"
          >
            {{ creating ? '注册中…' : (nodeLocked ? '下一步' : '注册节点并生成配置') }}
            <AppIcon v-if="!creating" name="chevron-right" :size="15" />
          </button>
          <template v-else-if="step === 3">
            <button class="btn btn-default" type="button" @click="restart">
              换一台机器重来
            </button>
            <button class="btn btn-primary" type="button" @click="next">
              去验证上线
              <AppIcon name="chevron-right" :size="15" />
            </button>
          </template>
          <template v-else>
            <NuxtLink to="/nodes" class="btn btn-primary">
              返回节点列表
            </NuxtLink>
          </template>
        </div>
      </div>
    </template>
  </div>
</template>
<script setup lang="ts">
import {
  CACHE_BACKEND_LABEL,
  EDGE_ENV_INSTALL_STEPS,
  humanBytes,
  recommendEdgeConfig,
  renderEdgeEnvFile,
  serializeEdgeProfile,
  summarizeHardware,
  type EdgeCacheBackend,
  type EdgeDiskType,
  type EdgeHardware,
  type EdgeSizingOverrides,
  type EdgeWorkload,
} from '~/utils/edgeSizing'
import { copyText } from '~/utils/clipboard'
import { friendlyErrorMessage } from '~/utils/friendlyError'

const api = useApi()
const auth = useAuthStore()
const toast = useToast()
const { ask } = useConfirm()

const steps = ['节点身份', '硬件画像', '容量规划', '生成配置', '上线验证']

interface CreatedNode {
  node: any
  token: string
  commands: { binary: string; docker: string }
}

const step = ref(0)
const stepError = ref('')
const creating = ref(false)
const created = ref<CreatedNode | null>(null)
const tokenVisible = ref(false)
const tab = ref<'env' | 'binary' | 'docker'>('env')

const form = ref({
  name: '',
  region: '',
  public_ip: '',
  agent_url: '',
  country: 'CN',
  province: '',
  city: '',
  isp: '',
  weight: 100,
})

const hw = ref<EdgeHardware>({
  cpuCores: 4,
  memoryGb: 8,
  diskGb: 200,
  diskType: 'nvme' as EdgeDiskType,
  bandwidthMbps: 500,
  workload: 'web' as EdgeWorkload,
  sharedRedis: false,
})

const infra = ref({
  httpsEnabled: true,
  httpsListen: '0.0.0.0:443',
  // The management plane must be reachable by the control plane (purge, certs,
  // ACME), so it is configurable instead of hardcoded to loopback.
  adminListen: '127.0.0.1:8081',
  redisUrl: '',
  cacheRedisUrl: '',
  cacheBackend: 'auto' as EdgeCacheBackend,
  challengeSecret: '',
  wafRulepackSecret: '',
})

// `undefined` means "use the recommendation"; the inputs bind to these so an
// empty box never silently becomes 0.
const overrides = ref<EdgeSizingOverrides>({
  workerThreads: undefined,
  memoryCacheMiB: undefined,
  largeCacheGiB: undefined,
})

function optionalNumber(value: unknown): number | undefined {
  // `v-model.number` hands back '' when the operator clears the box, and 0 is a
  // meaningful override (it disables the large cache), so only undefined/''/NaN
  // fall back to the recommendation.
  if (value === undefined || value === null || value === '') return undefined
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}

const cleanOverrides = computed<EdgeSizingOverrides>(() => ({
  workerThreads: optionalNumber(overrides.value.workerThreads),
  memoryCacheMiB: optionalNumber(overrides.value.memoryCacheMiB),
  largeCacheGiB: optionalNumber(overrides.value.largeCacheGiB),
}))

/** Cross-field problems between AGENT_URL and the admin listener. */
const infraWarnings = computed(() => {
  const warnings: string[] = []
  const agent = form.value.agent_url.trim()
  const admin = infra.value.adminListen.trim()
  const loopback = /^(127\.|localhost|\[::1\])/i.test(admin)
  const agentHost = agent.replace(/^https?:\/\//, '').split(/[/:]/)[0] ?? ''
  const agentLoopback = /^(127\.|localhost|\[::1\]$)/i.test(agentHost)
  if (agent && loopback && !agentLoopback) {
    warnings.push(
      `AGENT_URL 指向 ${agentHost}，但管理面只监听 ${admin}：控制面无法回调该节点（刷新、证书、ACME 会失败）。同机部署可忽略；跨机请把管理面改为内网地址并在防火墙放行该端口。`,
    )
  }
  if (!/^[A-Za-z0-9.:[\]-]+:\d{1,5}$/.test(admin)) {
    warnings.push('管理面监听地址格式应为 IP:端口，例如 127.0.0.1:8081 或 10.0.0.10:8081。')
  }
  // Source of truth (apps/edge/src/main.rs): CC counters and the distributed
  // rate limiter need only REDIS_URL; the flight lock and L2 cache need
  // CACHE_BACKEND=redis plus an endpoint (CACHE_REDIS_URL, else REDIS_URL).
  const redisEndpoint = infra.value.redisUrl.trim()
  const cacheEndpoint = infra.value.cacheRedisUrl.trim()
  if (infra.value.cacheBackend === 'redis' && !redisEndpoint && !cacheEndpoint) {
    warnings.push(
      'CACHE_BACKEND=redis 但 REDIS_URL 与 CACHE_REDIS_URL 都为空：Edge 会告警并回退到本地缓存，合并锁也不会启用。',
    )
  }
  if (infra.value.cacheBackend !== 'redis' && (redisEndpoint || cacheEndpoint)) {
    warnings.push(
      `已填写 Redis 地址但 CACHE_BACKEND=${infra.value.cacheBackend}：CC 计数与分布式限流仍会跨节点共享，` +
        '而合并锁与 L2 缓存需要 CACHE_BACKEND=redis 才启用。',
    )
  }
  if (redisEndpoint && !hw.value.sharedRedis) {
    warnings.push(
      '已填写 REDIS_URL：CC 计数与分布式限流会用该 Redis 跨节点共享（区域实例即可，无需与控制面同一台）；' +
        '勾选「使用共享 Redis」只会额外输出 Redis 超时调优参数。',
    )
  }
  for (const url of [infra.value.redisUrl, infra.value.cacheRedisUrl]) {
    const value = url.trim()
    if (value && !/^rediss?:\/\//i.test(value)) {
      warnings.push(`Redis 地址必须以 redis:// 或 rediss:// 开头：${value}`)
    }
  }
  if (admin.endsWith(':80') || admin.endsWith(':443')) {
    warnings.push('管理面不要使用 80/443：那是数据面端口，管理接口不应暴露在业务端口上。')
  }
  return warnings
})

const nodeLocked = computed(() => created.value !== null)

const plan = computed(() =>
  recommendEdgeConfig(hw.value, {
    ...cleanOverrides.value,
    // `CACHE_BACKEND` comes from the runtime section, not the hardware form, so
    // it is merged in here to keep a single source of truth for the plan.
    cacheBackend: infra.value.cacheBackend,
  }),
)
const hardwareSummary = computed(() => summarizeHardware(hw.value))

const controlUrl = computed(() => {
  // The control plane is what the operator is looking at; the browser origin is
  // the only URL we can infer, and an explicit override wins when present.
  if (import.meta.client && window.location?.origin) return window.location.origin
  return ''
})

const envText = computed(() => {
  if (!created.value) return ''
  return renderEdgeEnvFile({
    nodeId: form.value.name.trim(),
    region: form.value.region.trim(),
    publicIp: form.value.public_ip.trim(),
    agentUrl: form.value.agent_url.trim() || `http://${form.value.public_ip.trim()}:8081`,
    token: created.value.token,
    controlUrl: controlUrl.value || 'http://<控制面地址>:8080',
    adminListen: infra.value.adminListen || '127.0.0.1:8081',
    httpsEnabled: infra.value.httpsEnabled,
    httpsListen: infra.value.httpsListen,
    redisUrl: infra.value.redisUrl,
    cacheRedisUrl: infra.value.cacheRedisUrl,
    challengeSecret: infra.value.challengeSecret,
    wafRulepackSecret: infra.value.wafRulepackSecret,
    hardware: hw.value,
    plan: plan.value,
  })
})

const installSteps = EDGE_ENV_INSTALL_STEPS

const activeContent = computed(() => {
  if (tab.value === 'env') return envText.value
  if (!created.value) return ''
  return tab.value === 'docker' ? created.value.commands.docker : created.value.commands.binary
})

const tabLabel = computed(() =>
  tab.value === 'env' ? 'edge.env' : tab.value === 'docker' ? 'Docker 命令' : '二进制命令',
)

/** Mirrors `validate_region` in apps/control/src/api/node.rs. */
function validRegion(value: string): boolean {
  return /^[A-Za-z0-9._-]{0,64}$/.test(value)
}

/** Mirrors `validate_agent_url`: plain http(s) origin, no shell metacharacters. */
function validAgentUrl(value: string): boolean {
  if (!value) return true
  if (value.length > 256) return false
  if (!/^https?:\/\//.test(value)) return false
  const rest = value.replace(/^https?:\/\//, '')
  if (!rest || !/^[A-Za-z0-9]/.test(rest)) return false
  return !/[\s"'`;&|$()<>]/.test(value)
}

function validIp(value: string): boolean {
  if (!value) return false
  // Deliberately permissive: IPv4, IPv6 and hostnames are all acceptable here,
  // and GeoDNS does the real resolution.
  return /^[A-Za-z0-9.:_-]{1,64}$/.test(value)
}

function validateStep(index: number): string {
  if (index === 0) {
    const name = form.value.name.trim()
    if (!name) return '请填写节点名称'
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(name)) {
      return '节点名称只能包含字母、数字、点、下划线与连字符（最长 64 个字符）'
    }
    if (!validRegion(form.value.region.trim())) {
      return '区域标签只能包含字母、数字、点、下划线与连字符'
    }
    if (!validIp(form.value.public_ip.trim())) {
      return '请填写该节点对访客可达的公网 IP'
    }
    if (!validAgentUrl(form.value.agent_url.trim())) {
      return 'Agent 地址必须是 http(s)://主机[:端口]，不能带路径或特殊字符'
    }
    return ''
  }
  if (index === 1) {
    if (!Number(hw.value.cpuCores) || hw.value.cpuCores < 1) return '请填写 CPU 核数（至少 1 核）'
    if (!Number(hw.value.memoryGb) || hw.value.memoryGb < 1) return '请填写内存容量（至少 1 GiB）'
    if (Number(hw.value.diskGb) < 0) return '磁盘容量不能为负数'
    // 0 is allowed: the plan then warns that the node is memory-only.
    // A malformed listen address makes the edge process fail to start, so it is
    // a hard error rather than one of the advisory warnings above.
    const listen = /^[A-Za-z0-9.:[\]-]+:\d{1,5}$/
    if (!listen.test(infra.value.adminListen.trim())) {
      return '管理面监听地址格式应为 IP:端口，例如 127.0.0.1:8081'
    }
    if (infra.value.httpsEnabled && !listen.test(infra.value.httpsListen.trim())) {
      return 'HTTPS 监听地址格式应为 IP:端口，例如 0.0.0.0:443'
    }
    return ''
  }
  return ''
}

async function next() {
  stepError.value = ''
  const message = validateStep(step.value)
  if (message) {
    stepError.value = message
    return
  }
  if (step.value === 2) {
    const ok = await ensureNode()
    if (!ok) return
  }
  if (step.value === 3) {
    startPolling()
  }
  step.value = Math.min(step.value + 1, steps.length - 1)
}

function prev() {
  stepError.value = ''
  step.value = Math.max(step.value - 1, 0)
}

/** `<select>` yields a plain string; narrow it back to the union it belongs to. */
function setDiskType(value: string) {
  hw.value.diskType = value as EdgeDiskType
}

function setWorkload(value: string) {
  hw.value.workload = value as EdgeWorkload
}

function setCacheBackend(value: string) {
  infra.value.cacheBackend = value as EdgeCacheBackend
}

/**
 * Payload stored on the node so the detail drawer can rebuild the same file.
 *
 * Every value that changes the rendered `edge.env` must be here, otherwise the
 * drawer silently disagrees with the wizard (Redis settings were the last gap).
 */
function currentProfile() {
  return {
    hardware: { ...hw.value },
    infra: {
      httpsEnabled: infra.value.httpsEnabled,
      httpsListen: infra.value.httpsListen,
      adminListen: infra.value.adminListen,
      redisUrl: infra.value.redisUrl.trim(),
      cacheRedisUrl: infra.value.cacheRedisUrl.trim(),
      cacheBackend: infra.value.cacheBackend,
      // Shared secrets are part of the profile so the drawer renders the same
      // CHALLENGE_SECRET / WAF_RULEPACK_SECRET the wizard produced.
      challengeSecret: infra.value.challengeSecret.trim(),
      wafRulepackSecret: infra.value.wafRulepackSecret.trim(),
    },
  }
}

/** Register the node exactly once; later visits only re-sync the profile. */
async function ensureNode(): Promise<boolean> {
  if (created.value) {
    await syncProfile()
    return true
  }
  creating.value = true
  try {
    const res = await api.post<CreatedNode>('/api/v1/nodes', {
      name: form.value.name.trim(),
      region: form.value.region.trim(),
      agent_url: form.value.agent_url.trim(),
      public_ip: form.value.public_ip.trim(),
      country: form.value.country.trim().toUpperCase() || 'CN',
      province: form.value.province.trim(),
      city: form.value.city.trim(),
      isp: form.value.isp.trim(),
      weight: Number(form.value.weight) || 100,
      edge_profile: serializeEdgeProfile(currentProfile()),
    })
    created.value = res
    toast.success('节点已注册，配置已按硬件生成')
    return true
  } catch (e: any) {
    const message = friendlyErrorMessage(e?.data?.error, '注册节点失败，请稍后重试')
    stepError.value = message
    toast.error(message)
    return false
  } finally {
    creating.value = false
  }
}

/**
 * Push the current hardware profile to the node.
 *
 * Only the profile is sent: the wizard never rewrites identity fields here, so
 * a node that is already serving traffic cannot be renamed or re-pointed by a
 * late "next" click.
 */
async function syncProfile() {
  const id = created.value?.node?.id
  if (!id) return
  try {
    await api.put(`/api/v1/nodes/${id}`, {
      edge_profile: serializeEdgeProfile(currentProfile()),
    })
  } catch {
    // Non-fatal: the local profile still renders the file the operator needs.
  }
}

async function restart() {
  const ok = await ask({
    title: '换一台机器重来',
    message: created.value
      ? `已注册的节点 ${created.value.node.name} 仍会留在控制台，需要你稍后在节点列表里删除。确认重新开始？`
      : '确认清空当前填写的内容？',
    confirmText: '重新开始',
    danger: Boolean(created.value),
  })
  if (!ok) return
  stopPolling()
  created.value = null
  tokenVisible.value = false
  tab.value = 'env'
  stepError.value = ''
  liveNode.value = null
  // Hand-tuned numbers belong to the node we just abandoned; the next machine
  // should start from its own recommendation.
  overrides.value = {
    workerThreads: undefined,
    memoryCacheMiB: undefined,
    largeCacheGiB: undefined,
  }
  step.value = 0
}

function copy(text: string, label: string) {
  if (!text) return
  copyText(text).then((ok) => {
    if (ok) toast.success(`${label}已复制`)
    else toast.error('复制失败，请手动选择文本')
  })
}

function downloadEnv() {
  if (!import.meta.client || !envText.value) return
  const blob = new Blob([envText.value], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `edge-${form.value.name.trim() || 'node'}.env`
  a.click()
  URL.revokeObjectURL(url)
}

/** Bytes are easier to read than "8388608" in the plan table. */
function displayValue(item: { key: string; value: string }) {
  if (!/_BYTES$/.test(item.key)) return item.value
  const bytes = Number(item.value)
  if (!Number.isFinite(bytes)) return item.value
  return `${item.value}  (${humanBytes(bytes)})`
}
// ------------------------------------------------------------ 上线轮询
const liveNode = ref<any>(null)
const polling = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

/** Whether the control plane shows this node as reachable right now. */
const isLive = computed(() => (liveNode.value?.status || '') === 'online')

// StatusTag only accepts a fixed set of tones, so the map is typed with the
// same union instead of a loose `string`.
type LiveTone = 'success' | 'warning' | 'danger' | 'neutral'

const liveStatusObject = computed<{ label: string; tone: LiveTone }>(() => {
  const status = liveNode.value?.status || created.value?.node?.status || 'pending'
  const map: Record<string, { label: string; tone: LiveTone }> = {
    online: { label: '在线', tone: 'success' },
    pending: { label: '待接入', tone: 'warning' },
    offline: { label: '离线', tone: 'danger' },
    disabled: { label: '已停用', tone: 'neutral' },
  }
  return map[status] || { label: status, tone: 'neutral' }
})

const liveTone = computed(() => {
  const tone = liveStatusObject.value.tone
  return tone === 'success' ? 'is-ok' : tone === 'danger' ? 'is-bad' : ''
})

/** Read the node list and pick out this node; the API has no per-node poll. */
async function pollOnce() {
  const id = created.value?.node?.id
  if (!id) return
  try {
    const nodes = (await api.get<any[]>('/api/v1/nodes')) || []
    const found = nodes.find((n) => n.id === id)
    if (found) liveNode.value = found
    if (found?.status === 'online') stopPolling()
  } catch {
    // A transient failure just means we try again on the next tick.
  }
}

function startPolling() {
  if (!created.value) return
  polling.value = true
  void pollOnce()
  if (pollTimer) return
  pollTimer = setInterval(() => {
    void pollOnce()
  }, 3000)
}

function stopPolling() {
  polling.value = false
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

onUnmounted(stopPolling)

// --------------------------------------------------------------- 提示文案
const footHint = computed(() => {
  if (step.value === 0) return '名称与公网 IP 注册后不可修改'
  if (step.value === 1) return `将按 ${hardwareSummary.value} 推导容量`
  if (step.value === 2) return nodeLocked.value ? '节点已注册，调整后配置会实时重算' : '下一步会在控制台注册该节点'
  if (step.value === 3) return '令牌只展示一次，请先复制或下载配置'
  return liveStatusObject.value.label === '在线' ? '节点已上线' : '节点启动后约 15 秒上线'
})
</script>


<style scoped>
/* ------------------------------------------------------------- wizard shell */
.wizard-steps {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
  flex-wrap: wrap;
}

.wizard-step {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  border-radius: 20px;
  background: var(--card);
  border: 1px solid var(--border);
  font-size: 13px;
  color: var(--text-3);
}

.wizard-step.active {
  border-color: var(--brand);
  color: var(--brand);
  background: var(--brand-bg);
}

.wizard-step.done {
  color: var(--success);
  border-color: var(--success-border);
}

.wizard-index {
  width: 20px;
  height: 20px;
  border-radius: 50%;
  background: var(--bg);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 11px;
  flex: none;
}

.wizard-hero {
  display: flex;
  gap: 14px;
  align-items: flex-start;
  margin-bottom: 8px;
}

.wizard-icon {
  width: 48px;
  height: 48px;
  border-radius: 12px;
  background: var(--brand-bg);
  color: var(--brand);
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
}

.wizard-title {
  font-size: 17px;
  font-weight: 600;
}

.wizard-desc {
  margin-top: 4px;
  font-size: 13px;
  line-height: 1.6;
  color: var(--text-3);
}

.wizard-foot {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 14px 20px;
  border-top: 1px solid var(--divider);
  background: #fbfdff;
}

.foot-hint {
  font-size: 12px;
}

.step-error {
  font-size: 13px;
  margin: 0;
}

/* Optional groups collapse so the main path stays short. */
.optional-block {
  padding: 10px 12px;
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius);
  background: transparent;
}

.optional-block summary {
  cursor: pointer;
  font-size: 12.5px;
  color: var(--text-2);
  user-select: none;
}

.optional-block[open] summary {
  margin-bottom: 12px;
}

.toggle-list {
  display: flex;
  flex-wrap: wrap;
  gap: 10px 24px;
}


/* ---------------------------------------------------------- plan summary */
.metric-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 10px;
}

.metric-card {
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--brand) 3%, var(--card));
}

.metric-label {
  font-size: 11px;
  color: var(--text-3);
}

.metric-value {
  margin-top: 4px;
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
  font-variant-numeric: tabular-nums;
}

.metric-sub {
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-3);
}

.alert-list {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.override-block {
  padding: 12px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.override-title {
  font-size: 12.5px;
  color: var(--text-2);
  margin-bottom: 10px;
}

.override-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}

.override-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 11.5px;
  color: var(--text-3);
}

.plan-table td {
  vertical-align: top;
}

.plan-key {
  font-size: 12px;
  color: var(--text);
}

.plan-value {
  font-size: 12px;
  color: var(--brand);
  word-break: break-all;
}

.plan-reason {
  font-size: 12px;
  line-height: 1.55;
}

.tag-manual {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 5px;
  border-radius: 4px;
  background: var(--warning-bg);
  border: 1px solid var(--warning-border);
  color: var(--warning);
  font-size: 10px;
  vertical-align: middle;
}

/* --------------------------------------------------------- generated output */
.copy-row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.copy-row .input {
  flex: 1;
  min-width: 180px;
}

.segmented {
  display: inline-flex;
  gap: 4px;
  padding: 3px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.segmented button {
  border: none;
  background: transparent;
  padding: 6px 12px;
  border-radius: 5px;
  font-size: 12.5px;
  color: var(--text-2);
  cursor: pointer;
}

.segmented button.active {
  background: var(--card);
  color: var(--brand);
  box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
}

.command-box {
  position: relative;
  background: #0f172a;
  border-radius: var(--radius);
  padding: 14px 16px;
  max-height: 420px;
  overflow: auto;
}

.command-box pre {
  margin: 0;
  color: #d6e8ff;
  font-size: 12.5px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-all;
}

.command-box.sub {
  max-height: 200px;
}

.copy-float {
  position: sticky;
  top: 0;
  float: right;
  background: rgba(255, 255, 255, 0.12);
  border-color: rgba(255, 255, 255, 0.2);
  color: #fff;
}

.copy-float:hover {
  color: #fff;
  border-color: #fff;
}

.tips {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 14px;
  background: #fafbfc;
  border: 1px solid var(--border);
  border-radius: var(--radius);
}

.tip-row {
  display: flex;
  gap: 8px;
  font-size: 12.5px;
  color: var(--text-2);
  line-height: 1.6;
}

.tip-index {
  width: 18px;
  height: 18px;
  border-radius: 50%;
  background: var(--brand-bg);
  color: var(--brand);
  font-size: 11px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex: none;
  margin-top: 1px;
}

/* ---------------------------------------------------------- live status */
.status-panel {
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.status-panel.is-ok {
  border-color: var(--success-border);
  background: var(--success-bg);
}

.status-panel.is-bad {
  border-color: var(--danger-border);
  background: var(--danger-bg);
}

.status-main {
  display: flex;
  align-items: center;
  gap: 10px;
}

.status-name {
  font-size: 13px;
  color: var(--text);
}

.status-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 14px;
  margin-top: 8px;
  font-size: 12px;
  color: var(--text-3);
}

.text-multi {
  min-width: 0;
}

@media (max-width: 720px) {
  .metric-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .override-grid {
    grid-template-columns: 1fr;
  }

  .wizard-foot {
    flex-wrap: wrap;
  }
}
</style>


