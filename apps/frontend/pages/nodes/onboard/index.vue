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
        <div v-for="(s, i) in steps" :key="s" class="wizard-step" :class="{ active: step === i, done: step > i }">
          <span class="wizard-index">{{ step > i ? '✓' : i + 1 }}</span>
          <span>{{ s }}</span>
        </div>
      </div>

      <div v-if="nodeLocked" class="alert alert-info">
        <AppIcon name="info" :size="16" class="icon" />
        <span>
          节点 <b>{{ created?.node?.name }}</b> 已在控制台注册，身份（名称 / 区域 / 公网 IP）已锁定；
          硬件与网络参数仍可调整，保存后只会重新生成 edge.env，不会重复注册。需要改名请删除该节点后重新接入。
        </span>
      </div>

      <div v-if="reusedFrom.length" class="alert alert-info">
        <AppIcon name="info" :size="16" class="icon" />
        <span>
          已从节点 <b>{{ reusedFrom.join('、') }}</b> 复用共享 Redis / CHALLENGE_SECRET / WAF_RULEPACK_SECRET，
          避免多节点配置不一致。请确认新节点与它在同一区域网络，并按需覆盖。
        </span>
      </div>

      <div class="card">
        <div class="card-body">
          <!-- 步骤 1：节点身份 -->
          <div v-if="step === 0" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon">
                <AppIcon name="node" :size="24" />
              </div>
              <div>
                <div class="wizard-title">这个节点叫什么、放在哪里？</div>
                <div class="wizard-desc">
                  名称是节点在控制台与心跳中的唯一标识，必须与边缘端的 NODE_ID 完全一致；
                  部署方式决定管理面监听和控制面回调地址，二者由向导自动保持一致。
                </div>
              </div>
            </div>
            <div class="form-grid">
              <div class="field span-2">
                <label class="field-label">节点名称 <span class="req">*</span></label>
                <input v-model="form.name" class="input mono" placeholder="edge-hk-01" :disabled="nodeLocked"
                  @keyup.enter="next" />
                <span class="field-hint">
                  仅允许字母、数字、点、下划线与连字符，最长 64 字符；它会原样写入 edge.env 的 NODE_ID。
                </span>
              </div>
              <div class="field">
                <label class="field-label">区域标签</label>
                <input v-model="form.region" class="input multi" placeholder="cn-hongkong" :disabled="nodeLocked" />
                <span class="field-hint">只用字母 / 数字 / . / _ / -，用于展示与排障分组。</span>
              </div>
              <div class="field">
                <label class="field-label">公网 IP <span class="req">*</span></label>
                <input v-model="form.public_ip" class="input multi" placeholder="203.0.113.21" :disabled="nodeLocked" />
                <span class="field-hint">GeoDNS 返回这个地址，必须是对访客可达的 IP。</span>
              </div>
              <div class="field span-2">
                <label class="field-label">部署方式</label>
                <select class="select" :value="infra.deployment"
                  @change="setDeployment(($event.target as HTMLSelectElement).value)">
                  <option v-for="(label, value) in DEPLOYMENT_LABEL" :key="value" :value="value">
                    {{ label }}
                  </option>
                </select>
                <span class="field-hint">{{ DEPLOYMENT_DESC[infra.deployment] }}</span>
              </div>
            </div>

            <div class="derived-box">
              <div class="derived-title">由部署方式推导的回调地址</div>
              <div class="derived-row">
                <span class="derived-key">EDGE_ADMIN_LISTEN（管理面）</span>
                <span class="mono derived-val">{{ infra.adminListen || '待填写' }}</span>
              </div>
              <div class="derived-row">
                <span class="derived-key">AGENT_URL（控制面回调）</span>
                <span class="mono derived-val">{{ effectiveAgentUrl || '待填写公网 IP 或自定义地址' }}</span>
              </div>
              <div v-if="infra.deployment === 'custom'" class="form-grid">
                <div class="field">
                  <label class="field-label">管理面监听</label>
                  <input v-model="infra.adminListen" class="input mono" placeholder="10.0.0.21:8081" />
                  <span class="field-hint">Edge 以 SocketAddr 解析，必须是 IP:端口，不能写主机名。</span>
                </div>
                <div class="field">
                  <label class="field-label">AGENT_URL</label>
                  <input v-model="infra.agentUrl" class="input mono" placeholder="http://10.0.0.21:8081" />
                  <span class="field-hint">必须指向上面的管理面端口，且控制面能访问。</span>
                </div>
              </div>
              <span class="field-hint">
                管理面承载 purge、证书下发和 ACME 回调；跨机部署时只允许控制面来源访问，不要对访客开放。
              </span>
            </div>

            <div v-if="identityWarnings.length" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <div class="alert-list">
                <span v-for="w in identityWarnings" :key="w">{{ w }}</span>
              </div>
            </div>

            <details class="optional-block">
              <summary>调度归属（可选：国家 / 省份 / 城市 / 运营商 / 权重）</summary>
              <div class="form-grid">
                <div class="field">
                  <label class="field-label">国家/地区代码</label>
                  <input v-model="form.country" class="input" list="edge-country-codes" maxlength="2" placeholder="CN"
                    :disabled="nodeLocked" />
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
                  <input v-model="form.province" class="input multi" placeholder="广东" :disabled="nodeLocked" />
                </div>
                <div class="field">
                  <label class="field-label">城市</label>
                  <input v-model="form.city" class="input multi" placeholder="深圳" :disabled="nodeLocked" />
                </div>
                <div class="field">
                  <label class="field-label">运营商</label>
                  <input v-model="form.isp" class="input multi" placeholder="电信 / BGP" :disabled="nodeLocked" />
                </div>
                <div class="field">
                  <label class="field-label">调度权重</label>
                  <input v-model.number="form.weight" class="input" type="number" min="0" max="1000"
                    :disabled="nodeLocked" />
                  <span class="field-hint">数值越大越优先，默认 100。</span>
                </div>
              </div>
            </details>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>

          <!-- 步骤 2：硬件画像 -->
          <div v-else-if="step === 1" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon">
                <AppIcon name="zap" :size="24" />
              </div>
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
                <input v-model.number="hw.cpuCores" class="input" type="number" min="1" max="128" />
                <span class="field-hint">决定工作线程数；单核会把 TLS 与回源握手串行。</span>
              </div>
              <div class="field">
                <label class="field-label">内存（GiB）<span class="req">*</span></label>
                <input v-model.number="hw.memoryGb" class="input" type="number" min="1" max="512" />
                <span class="field-hint">内存的 25% 划给 L1 缓存，上限 8 GiB。</span>
              </div>
              <div class="field">
                <label class="field-label">缓存磁盘容量（GiB）</label>
                <input v-model.number="hw.diskGb" class="input" type="number" min="0" max="100000" />
                <span class="field-hint">填 0 表示只做内存缓存，重启后缓存全丢。</span>
              </div>
              <div class="field">
                <label class="field-label">磁盘类型</label>
                <select class="select" :value="hw.diskType"
                  @change="setDiskType(($event.target as HTMLSelectElement).value)">
                  <option value="nvme">NVMe SSD</option>
                  <option value="sata-ssd">SATA SSD</option>
                  <option value="hdd">机械盘 HDD</option>
                </select>
                <span class="field-hint">决定分片大小与写队列：机械盘分片放大到 4 MiB。</span>
              </div>
              <div class="field">
                <label class="field-label">出口带宽（Mbps）</label>
                <input v-model.number="hw.bandwidthMbps" class="input" type="number" min="0" max="100000" />
                <span class="field-hint">用于校验核数是否够用，并影响连接复用与超时。</span>
              </div>
              <div class="field">
                <label class="field-label">主要业务类型</label>
                <select class="select" :value="hw.workload"
                  @change="setWorkload(($event.target as HTMLSelectElement).value)">
                  <option value="web">网页 / 小文件</option>
                  <option value="mixed">混合业务</option>
                  <option value="video">视频 / 大文件点播</option>
                </select>
                <span class="field-hint">决定默认 TTL、大对象缓存门槛与回源超时。</span>
              </div>
            </div>

            <div class="form-grid">
              <div class="field span-2">
                <label class="field-label">节点角色</label>
                <select class="select" :value="hw.role" @change="setRole(($event.target as HTMLSelectElement).value)">
                  <option v-for="(label, value) in NODE_ROLE_LABEL" :key="value" :value="value">
                    {{ label }}（{{ value }}）
                  </option>
                </select>
                <span class="role-note">{{ NODE_ROLE_DESC[hw.role] }}</span>
              </div>
            </div>

            <div class="toggle-list">
              <label class="check">
                <input v-model="hw.sharedRedis" type="checkbox" />
                使用共享 Redis（区域实例即可，无需与控制面同一台）
              </label>
              <label class="check">
                <input v-model="infra.httpsEnabled" type="checkbox" />
                启用 HTTPS 监听（证书由控制面同步）
              </label>
            </div>
            <span class="field-hint">
              共享 Redis 勾选后才会按带宽输出 CACHE_FLIGHT_TIMEOUT_MS / CC_REDIS_TIMEOUT_MS；
              是否真正跨节点共享由「高级：缓存后端与共享 Redis」决定。
            </span>

            <div class="form-grid">
              <div class="field">
                <label class="field-label">HTTP 监听地址</label>
                <input v-model="infra.httpListen" class="input mono" placeholder="0.0.0.0:80" />
                <span class="field-hint">Pingora 数据面入口；生产通常监听 80。</span>
              </div>
              <div class="field">
                <label class="field-label">HTTPS 监听地址</label>
                <input v-model="infra.httpsListen" class="input mono" :disabled="!infra.httpsEnabled"
                  placeholder="0.0.0.0:443" />
                <span class="field-hint">非 443 端口会自动写入 EDGE_HTTPS_REDIRECT_PORT。</span>
              </div>
            </div>

            <details class="optional-block">
              <summary>高级：缓存后端与共享 Redis（当前推导：{{ plan.metrics.cacheBackend }}）</summary>
              <div class="form-grid">
                <div class="field">
                  <label class="field-label">CACHE_BACKEND</label>
                  <select class="select" :value="infra.cacheBackend"
                    @change="setCacheBackend(($event.target as HTMLSelectElement).value)">
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
                  <input v-model="infra.redisUrl" class="input mono" placeholder="redis://127.0.0.1:6379/0" />
                  <span class="field-hint">
                    CC 计数、跨节点合并锁与 L2 回退共用；留空则这些能力只在单节点进程内生效。
                  </span>
                </div>
                <div class="field span-2">
                  <label class="field-label">CACHE_REDIS_URL（L2 专用，可选）</label>
                  <input v-model="infra.cacheRedisUrl" class="input mono" placeholder="留空复用 REDIS_URL" />
                  <span class="field-hint">
                    仅 CACHE_BACKEND=redis 时启用；地址含密码时会随硬件画像一并存储。
                  </span>
                </div>
              </div>
            </details>

            <div v-if="infraWarnings.length" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <div class="alert-list">
                <span v-for="w in infraWarnings" :key="w">{{ w }}</span>
              </div>
            </div>

            <details class="optional-block">
              <summary>共享密钥（CHALLENGE_SECRET 已自动生成；多节点会复用同一值）</summary>
              <div class="form-grid">
                <div class="field">
                  <label class="field-label">CHALLENGE_SECRET</label>
                  <div class="secret-row">
                    <input v-model="infra.challengeSecret" class="input mono" autocomplete="off"
                      placeholder="多节点必须完全一致" />
                    <button class="btn btn-default btn-sm" type="button" @click="randomizeChallengeSecret">
                      生成
                    </button>
                    <button class="btn btn-default btn-sm" type="button" :disabled="!infra.challengeSecret"
                      @click="copy(infra.challengeSecret, 'CHALLENGE_SECRET')">
                      复制
                    </button>
                  </div>
                  <span class="field-hint">
                    已自动生成，并会随节点画像保存；后续节点打开向导时会自动复用同一值。
                    修改后请同步更新所有节点，否则质询无法跨节点通过。
                  </span>
                </div>
                <div class="field">
                  <label class="field-label">WAF_RULEPACK_SECRET</label>
                  <div class="secret-row">
                    <input v-model="infra.wafRulepackSecret" class="input mono" type="password" autocomplete="off" />
                    <button class="btn btn-default btn-sm" type="button" :disabled="!infra.wafRulepackSecret"
                      @click="copy(infra.wafRulepackSecret, 'WAF_RULEPACK_SECRET')">
                      复制
                    </button>
                  </div>
                  <span class="field-hint">
                    需与控制面 /etc/lagran/control.env 完全一致，否则签名规则包验签失败。
                  </span>
                </div>
              </div>
            </details>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>

          <!-- 步骤 3：容量规划 -->
          <div v-else-if="step === 2" class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon">
                <AppIcon name="stats" :size="24" />
              </div>
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

            <div v-if="hw.role === 'shield'" class="alert alert-info">
              <AppIcon name="shield" :size="16" class="icon" />
              <span>
                这是 Origin Shield：edge.env 会自动写入 EDGE_SHIELD_DISABLED=true，
                避免 Shield 自己回源到自己；同时按区域汇聚场景启用更大的大对象缓存。
              </span>
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
                  <input v-model.number="overrides.workerThreads" class="input" type="number" min="1" max="256"
                    :placeholder="String(plan.metrics.workerThreads)" />
                </label>
                <label class="override-field">
                  <span>内存缓存（MiB）</span>
                  <input v-model.number="overrides.memoryCacheMiB" class="input" type="number" min="16"
                    :placeholder="String(Math.round(plan.metrics.memoryCacheBytes / 1048576))" />
                </label>
                <label class="override-field">
                  <span>大对象缓存（GiB，0 = 关闭）</span>
                  <input v-model.number="overrides.largeCacheGiB" class="input" type="number" min="0"
                    :placeholder="String(Math.round(plan.metrics.largeCacheBytes / 1073741824))" />
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
              <div class="wizard-icon">
                <AppIcon name="logs" :size="24" />
              </div>
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

            <div v-if="created?.waf_rulepack_configured === false" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <span>
                控制面没有配置 WAF_RULEPACK_SECRET：签名 WAF 规则包无法下发，Edge 会拒绝验签。
                请先在控制面 /etc/lagran/control.env 配置，再重新生成节点配置。
              </span>
            </div>

            <div class="derived-box">
              <div class="derived-row">
                <span class="derived-key">CONTROL_URL（控制面）</span>
                <span class="mono derived-val">{{ controlUrl || '未解析，请设置 CONTROL_PUBLIC_URL' }}</span>
              </div>
              <div class="derived-row">
                <span class="derived-key">管理面 · 回调地址</span>
                <span class="mono derived-val">
                  {{ effectiveAdminHostPort }} · {{ effectiveAgentUrl || '未设置' }}
                </span>
              </div>
            </div>

            <div class="field">
              <div class="field-label">节点令牌</div>
              <div class="copy-row">
                <input class="input mono" :type="tokenVisible ? 'text' : 'password'" :value="created?.token || ''"
                  readonly />
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

            <div class="field">
              <div class="field-label">一键安装脚本（写入 edge.env、安装并重启）</div>
              <div class="command-box">
                <pre class="mono">{{ oneClickInstallScript }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button"
                  @click="copy(oneClickInstallScript, '一键安装脚本')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
              </div>
              <span class="field-hint">
                脚本包含节点令牌，请通过安全通道粘贴到节点上的 root shell 执行，不要提交到仓库或工单系统。
                它会在安装前写入本页的 edge.env，因此不会再被安装器的默认配置覆盖。
              </span>
            </div>

            <details class="optional-block">
              <summary>只执行安装器（适合已手动放好 edge.env）</summary>
              <div class="command-box sub">
                <pre class="mono">{{ installCommand }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(installCommand, '安装命令')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
              </div>
              <span class="field-hint">
                安装器需要 root，命令用 sudo env 传递 AGENT_TOKEN / NODE_ID；节点上必须先存在本页的 edge.env。
              </span>
            </details>

            <div class="field">
              <div class="field-label">edge.env（按当前硬件与角色生成）</div>
              <!-- <div class="command-box">
                <pre class="mono">{{ envText }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(envText, 'edge.env')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
              </div> -->
            </div>

            <div class="flex-between">
              <span class="text-muted" style="font-size: 12px">
                {{ envText.split('\n').length }} 行 · 含硬件推导注释 · 权限 600
              </span>
              <button class="btn btn-default btn-sm" type="button" @click="downloadEnv">
                下载 edge.env
              </button>
            </div>

            <div class="field">
              <div class="field-label">手动落位与重启（不用一键脚本时）</div>
              <div class="command-box sub">
                <pre class="mono">{{ installSteps }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(installSteps, '安装命令')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
              </div>
            </div>

            <details class="optional-block">
              <summary>先做一次配置校验（不监听端口）</summary>
              <div class="command-box sub">
                <pre class="mono">{{ checkSteps }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button" @click="copy(checkSteps, '校验命令')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
              </div>
            </details>

            <div class="tips">
              <div class="tip-row">
                <span class="tip-index">1</span>
                <span>
                  把 edge.env 与 lagran-edge 二进制一起上传到节点，配置放到 /etc/lagran/edge.env；
                  若尚未安装二进制，可先执行 install.sh edge（已存在 edge.env 时不会覆盖）。
                </span>
              </div>
              <div class="tip-row">
                <span class="tip-index">2</span>
                <span>确认节点能访问控制面 {{ controlUrl || '（控制面地址）' }}，且 EDGE_LISTEN 端口对访客开放。</span>
              </div>
              <div class="tip-row">
                <span class="tip-index">3</span>
                <span>
                  确认控制面能访问管理面 {{ effectiveAdminHostPort }}；跨机部署请在防火墙只放行控制面来源。
                </span>
              </div>
            </div>

            <div v-if="controlUrlLooksLoopback" class="alert alert-warning">
              <AppIcon name="alert" :size="16" class="icon" />
              <span>
                控制面地址是回环地址 {{ controlUrl }}：如果 Edge 不在控制面同机，心跳会失败。
                请在控制面设置 CONTROL_PUBLIC_URL 后重新打开向导。
              </span>
            </div>

            <p v-if="stepError" class="text-danger step-error">{{ stepError }}</p>
          </div>

          <!-- 步骤 5：上线验证 -->
          <div v-else class="form-col">
            <div class="wizard-hero">
              <div class="wizard-icon">
                <AppIcon name="activity" :size="24" />
              </div>
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

            <div class="field">
              <div class="field-label">节点侧自检</div>
              <div class="command-box sub">
                <pre class="mono">{{ verificationSteps }}</pre>
                <button class="btn btn-default btn-sm copy-float" type="button"
                  @click="copy(verificationSteps, '自检命令')">
                  <AppIcon name="copy" :size="14" />
                  复制
                </button>
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
                  节点到 {{ controlUrl }} 的网络是否可达，以及 journalctl -u lagran-edge 的启动日志。
                </span>
              </div>
              <div class="tip-row">
                <span class="tip-index">2</span>
                <span>
                  修改配置后需要重启服务；本向导生成的 edge.env 可随时在节点详情里通过
                  「edge.env 配置文件」重新获取。
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
          <button v-if="step > 0" class="btn btn-default" type="button" @click="prev">
            <AppIcon name="chevron-left" :size="15" />
            上一步
          </button>
          <span class="spacer" />
          <span class="text-muted foot-hint">{{ footHint }}</span>
          <button v-if="step === 0 || step === 1" class="btn btn-primary" type="button" @click="next">
            下一步
            <AppIcon name="chevron-right" :size="15" />
          </button>
          <button v-else-if="step === 2" class="btn btn-primary" type="button" :disabled="creating" @click="next">
            {{ creating ? '注册中…' : (nodeLocked ? '保存并生成配置' : '注册节点并生成配置') }}
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
  DEPLOYMENT_DESC,
  DEPLOYMENT_LABEL,
  EDGE_ENV_CHECK_STEPS,
  EDGE_ENV_INSTALL_STEPS,
  EDGE_PROFILE_DEFAULTS,
  NODE_ROLE_DESC,
  NODE_ROLE_LABEL,
  generateSecret,
  hostForUrl,
  humanBytes,
  isValidHttpUrl,
  isValidListen,
  isValidSocketAddr,
  parseEdgeProfile,
  recommendEdgeConfig,
  renderEdgeEnvFile,
  resolveDeployment,
  serializeEdgeProfile,
  splitListen,
  summarizeHardware,
  type EdgeCacheBackend,
  type EdgeDeploymentMode,
  type EdgeDiskType,
  type EdgeHardware,
  type EdgeNodeRole,
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
  /** Server-resolved control-plane base URL; see apps/control/src/api/node.rs. */
  control_url?: string
  /** False when the control plane has no WAF signing key configured. */
  waf_rulepack_configured?: boolean
}

const step = ref(0)
const stepError = ref('')
const creating = ref(false)
const created = ref<CreatedNode | null>(null)
const tokenVisible = ref(false)
const reusedFrom = ref<string[]>([])

const form = ref({
  name: '',
  region: '',
  public_ip: '',
  country: 'CN',
  province: '',
  city: '',
  isp: '',
  weight: 100,
})

const hw = ref<EdgeHardware>({ ...EDGE_PROFILE_DEFAULTS.hardware })

const infra = ref({ ...EDGE_PROFILE_DEFAULTS.infra })

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

/** Parse an http(s) URL into host/port without throwing. */
function parseHttpUrl(value: string): { host: string; port: string } | null {
  try {
    const url = new URL(value)
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null
    return {
      host: url.hostname.replace(/^\[/, '').replace(/\]$/, ''),
      port: url.port || (url.protocol === 'https:' ? '443' : '80'),
    }
  } catch {
    return null
  }
}

function isLoopbackAddress(host: string): boolean {
  const value = host.trim().replace(/^\[/, '').replace(/\]$/, '').toLowerCase()
  return value === 'localhost' || value === '::1' || value.startsWith('127.')
}

/**
 * `AGENT_URL` is derived, not typed, for the two guided deployment modes.
 * The edge parses `EDGE_ADMIN_LISTEN` as a SocketAddr and the control plane
 * calls `AGENT_URL`; if they disagree, heartbeats succeed while purge/cert/ACME
 * silently fail. Keeping them in one function removes that failure mode.
 */
const effectiveAgentUrl = computed(() => {
  if (infra.value.deployment !== 'custom') {
    return resolveDeployment(infra.value.deployment, form.value.public_ip.trim()).agentUrl
  }
  return infra.value.agentUrl.trim()
})

const effectiveAdminHostPort = computed(() => infra.value.adminListen || '127.0.0.1:8081')

/** Console origin is only a fallback; the API returns the authoritative value. */
const fallbackControlUrl = computed(() => {
  const base = (api.base as string || '').trim().replace(/\/+$/, '')
  if (base) return base
  if (import.meta.client && window.location?.origin) return window.location.origin
  return ''
})

const controlUrl = computed(() => created.value?.control_url || fallbackControlUrl.value)

const controlUrlLooksLoopback = computed(() => {
  const host = parseHttpUrl(controlUrl.value)?.host
  return Boolean(host && isLoopbackAddress(host))
})

function applyDeployment() {
  const derived = resolveDeployment(infra.value.deployment, form.value.public_ip.trim())
  if (!derived.adminListen) return
  infra.value.adminListen = derived.adminListen
  infra.value.agentUrl = derived.agentUrl
}

function setDeployment(value: string) {
  infra.value.deployment = value as EdgeDeploymentMode
  applyDeployment()
}

watch(
  () => form.value.public_ip,
  () => {
    if (infra.value.deployment !== 'custom') applyDeployment()
  },
)

/** Cross-field problems that do not block the wizard but will bite later. */
const identityWarnings = computed(() => {
  const warnings: string[] = []
  const admin = splitListen(infra.value.adminListen)
  const agent = parseHttpUrl(effectiveAgentUrl.value)

  if (infra.value.deployment === 'remote') {
    warnings.push('跨机部署：请在节点防火墙/安全组中只放行控制面来源访问管理面端口（默认 8081），不要对公网开放。')
    if (!form.value.public_ip.trim()) {
      warnings.push('跨机部署需要填写公网 IP，用于生成控制面可达的 AGENT_URL。')
    }
    if (admin && admin.host === '0.0.0.0') {
      warnings.push('管理面监听 0.0.0.0：仅在安全组/防火墙已限制来源时使用。')
    }
  }
  if (infra.value.deployment === 'same-host') {
    warnings.push('同机部署：控制面与节点必须运行在同一台机器，AGENT_URL 才能使用回环地址。')
  }

  if (admin && agent) {
    if (agent.port !== admin.port) {
      warnings.push(
        `AGENT_URL 端口 ${agent.port} 与 EDGE_ADMIN_LISTEN 端口 ${admin.port} 不一致，purge / 证书 / ACME 会失败。`,
      )
    }
    if (isLoopbackAddress(admin.host) && !isLoopbackAddress(agent.host)) {
      warnings.push('管理面只监听回环地址，但 AGENT_URL 使用非回环地址：控制面无法回调。')
    }
    if (!isLoopbackAddress(admin.host) && isLoopbackAddress(agent.host)) {
      warnings.push('AGENT_URL 指向回环地址，跨机控制面无法回调。')
    }
  }
  if (admin) {
    if (admin.port === '80' || admin.port === '443') {
      warnings.push('管理面不要使用 80/443：那是数据面端口。')
    }
    const httpPort = splitListen(infra.value.httpListen)?.port
    if (httpPort && httpPort === admin.port) {
      warnings.push('管理面端口与 HTTP 数据面端口相同，Edge 会拒绝启动。')
    }
    const httpsPort = splitListen(infra.value.httpsListen)?.port
    if (infra.value.httpsEnabled && httpsPort && httpsPort === admin.port) {
      warnings.push('管理面端口与 HTTPS 数据面端口相同，Edge 会拒绝启动。')
    }
  }
  return warnings
})

/** Sizing-adjacent warnings, shown on the hardware step. */
const infraWarnings = computed(() => {
  const warnings: string[] = []
  const redisEndpoint = infra.value.redisUrl.trim()
  const cacheEndpoint = infra.value.cacheRedisUrl.trim()

  // Source of truth (apps/edge/src/main.rs): CC counters and the distributed
  // rate limiter need only REDIS_URL; the flight lock and L2 cache need
  // CACHE_BACKEND=redis plus an endpoint (CACHE_REDIS_URL, else REDIS_URL).
  if (infra.value.cacheBackend === 'redis' && !redisEndpoint && !cacheEndpoint) {
    warnings.push(
      'CACHE_BACKEND=redis 但 REDIS_URL 与 CACHE_REDIS_URL 都为空：Edge 会回退到本地缓存，合并锁也不会启用。',
    )
  }
  if (infra.value.cacheBackend !== 'redis' && redisEndpoint) {
    warnings.push(
      `已填写 REDIS_URL 但 CACHE_BACKEND=${infra.value.cacheBackend}：CC 计数与分布式限流仍会跨节点共享，` +
      '而合并锁与 L2 缓存需要 CACHE_BACKEND=redis 才启用。',
    )
  }
  if (infra.value.cacheBackend !== 'redis' && cacheEndpoint && !redisEndpoint) {
    warnings.push(
      '已填写 CACHE_REDIS_URL，但 CACHE_BACKEND 不是 redis：该地址不会生效，CC 计数也不会跨节点共享。',
    )
  }
  if (redisEndpoint && !hw.value.sharedRedis) {
    warnings.push(
      '已填写 REDIS_URL：CC 计数与分布式限流会用该 Redis 跨节点共享（区域实例即可）；' +
      '勾选「使用共享 Redis」只会额外输出 Redis 超时调优参数。',
    )
  }
  for (const url of [infra.value.redisUrl, infra.value.cacheRedisUrl]) {
    const value = url.trim()
    if (value && !/^rediss?:\/\//i.test(value)) {
      warnings.push(`Redis 地址必须以 redis:// 或 rediss:// 开头：${value}`)
    }
  }
  if (!infra.value.challengeSecret.trim()) {
    warnings.push(
      'CHALLENGE_SECRET 为空：每个节点会用各自的 AGENT_TOKEN 派生，跨节点质询无法通过；多节点请填写相同值或点击「生成」。',
    )
  }
  if (!infra.value.wafRulepackSecret.trim()) {
    warnings.push(
      'WAF_RULEPACK_SECRET 为空：使用控制面签名规则包时必须填写，且要与 /etc/lagran/control.env 完全一致；不用签名规则包时可忽略。',
    )
  }
  if (infra.value.httpsEnabled && !form.value.public_ip.trim()) {
    warnings.push('启用 HTTPS 但未填公网 IP：DNS 无法调度，443 也可能没有匹配证书。')
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
    // Without an endpoint `redis` can only fall back locally; the planner
    // downgrades it and flags the result instead of emitting a broken config.
    redisConfigured: Boolean(infra.value.redisUrl.trim() || infra.value.cacheRedisUrl.trim()),
  }),
)
const hardwareSummary = computed(() => summarizeHardware(hw.value))

const envText = computed(() => {
  if (!created.value) return ''
  return renderEdgeEnvFile({
    nodeId: form.value.name.trim(),
    region: form.value.region.trim(),
    publicIp: form.value.public_ip.trim(),
    agentUrl: effectiveAgentUrl.value,
    token: created.value.token,
    controlUrl: controlUrl.value,
    httpListen: infra.value.httpListen,
    adminListen: infra.value.adminListen,
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

/** Public installer repository; keep it in sync with README / install.sh. */
const INSTALL_REPO = 'Lagran93/Lagran'

/** Quote a value for a POSIX shell single-quoted context. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`
}

/**
 * The installer requires root. `sudo env VAR=... bash` is deliberate: passing
 * the variables to `env` after sudo survives sudo's default env_reset, while
 * `sudo bash` alone would drop AGENT_TOKEN/NODE_ID.
 */
const installCommand = computed(() => {
  const token = created.value?.token || ''
  const name = form.value.name.trim()
  if (!token || !name) return ''
  return (
    `curl -fsSL https://raw.githubusercontent.com/${INSTALL_REPO}/main/install.sh ` +
    `| sudo env LAGRAN_REPO=${INSTALL_REPO} AGENT_TOKEN=${shellQuote(token)} ` +
    `NODE_ID=${shellQuote(name)} bash -s -- edge`
  )
})

/**
 * One copy-paste block for a fresh node.
 *
 * It writes the generated edge.env *before* running install.sh, because
 * `install.sh edge` keeps an existing /etc/lagran/edge.env instead of
 * overwriting it with its low-detail default. The heredoc is single-quoted so
 * the env file is written literally and no shell expansion touches secrets.
 */
const oneClickInstallScript = computed(() => {
  if (!created.value || !envText.value) return ''
  return `# 1) 写入本页生成的 edge.env（含节点令牌；安装器发现文件已存在会保留它）
# 注意：会覆盖节点上现有的 /etc/lagran/edge.env；如需保留旧配置请先备份。
sudo install -d -m 0750 /etc/lagran
sudo sh -c 'umask 077; cat > /etc/lagran/edge.env' <<'LAGRAN_EDGE_ENV_EOF'
${envText.value.trimEnd()}
LAGRAN_EDGE_ENV_EOF

# 2) 安装/更新 lagran-edge，并让新配置生效
${installCommand.value} && sudo systemctl restart lagran-edge

# 3) 可选：不监听端口的配置自检
sudo sh -c 'set -a; . /etc/lagran/edge.env; set +a; exec /opt/lagran/bin/lagran-edge check-config'`
})

const installSteps = EDGE_ENV_INSTALL_STEPS
const checkSteps = EDGE_ENV_CHECK_STEPS

const healthUrl = computed(() => {
  const admin = splitListen(infra.value.adminListen)
  if (!admin) return 'http://127.0.0.1:8081/__lagran/health'
  const host = admin.host === '0.0.0.0' || admin.host === '::' ? '127.0.0.1' : admin.host
  return `http://${hostForUrl(host)}:${admin.port}/__lagran/health`
})

const verificationSteps = computed(
  () => `# 本机健康检查（管理面）
curl -fsS ${healthUrl.value}

# 服务状态与启动摘要
sudo systemctl status lagran-edge --no-pager -l
sudo journalctl -u lagran-edge -n 50 --no-pager`,
)

/** `<select>` yields a plain string; narrow it back to the union it belongs to. */
function setDiskType(value: string) {
  hw.value.diskType = value as EdgeDiskType
}

function setWorkload(value: string) {
  hw.value.workload = value as EdgeWorkload
}

function setRole(value: string) {
  hw.value.role = value as EdgeNodeRole
}

function setCacheBackend(value: string) {
  infra.value.cacheBackend = value as EdgeCacheBackend
}

function randomizeChallengeSecret() {
  infra.value.challengeSecret = generateSecret(32)
}

/**
 * Reuse the shared settings already stored on an existing node.
 *
 * `CHALLENGE_SECRET` and `WAF_RULEPACK_SECRET` must be identical on every edge,
 * and the profile column is the only place the console knows them. Copying
 * them here means the second and later nodes do not need a manual copy/paste.
 */
async function loadSharedDefaults() {
  if (!auth.isAdmin) return
  try {
    const nodes = (await api.get<any[]>('/api/v1/nodes')) || []
    const names = new Set<string>()
    for (const node of nodes) {
      const profile = parseEdgeProfile(node?.edge_profile)
      if (!profile) continue
      if (!infra.value.challengeSecret && profile.infra.challengeSecret) {
        infra.value.challengeSecret = profile.infra.challengeSecret
        names.add(node.name)
      }
      if (!infra.value.wafRulepackSecret && profile.infra.wafRulepackSecret) {
        infra.value.wafRulepackSecret = profile.infra.wafRulepackSecret
        names.add(node.name)
      }
      if (!infra.value.redisUrl && profile.infra.redisUrl) {
        infra.value.redisUrl = profile.infra.redisUrl
        hw.value.sharedRedis = true
        names.add(node.name)
      }
      if (!infra.value.cacheRedisUrl && profile.infra.cacheRedisUrl) {
        infra.value.cacheRedisUrl = profile.infra.cacheRedisUrl
        names.add(node.name)
      }
    }
    reusedFrom.value = [...names]
  } catch {
    // An empty registry or a transient failure is not fatal; the operator can
    // still fill the fields manually.
  }
}

onMounted(async () => {
  if (infra.value.deployment !== 'custom') applyDeployment()
  await loadSharedDefaults()
  // A fresh deployment has no stored value to reuse. Generate one now: the
  // profile persists it and every later node reuses it, so a fleet stays
  // consistent without the operator inventing a secret.
  if (auth.isAdmin && !infra.value.challengeSecret.trim()) {
    infra.value.challengeSecret = generateSecret(32)
  }
})

/** Mirrors `validate_agent_url`: plain http(s) origin, no shell metacharacters. */
function validAgentUrl(value: string): boolean {
  return isValidHttpUrl(value, false)
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
    if (!/^[A-Za-z0-9._-]{0,64}$/.test(form.value.region.trim())) {
      return '区域标签只能包含字母、数字、点、下划线与连字符'
    }
    if (!validIp(form.value.public_ip.trim())) {
      return '请填写该节点对访客可达的公网 IP'
    }

    const admin = infra.value.adminListen.trim()
    if (!isValidSocketAddr(admin)) {
      return '管理面监听必须是 IP:端口（Edge 用 SocketAddr 解析，不能写主机名），例如 0.0.0.0:8081'
    }
    const adminParts = splitListen(admin)
    if (!adminParts) return '管理面监听格式无效'
    if (adminParts.port === '80' || adminParts.port === '443') {
      return '管理面不能使用 80/443，请换一个管理端口（例如 8081）'
    }
    const httpPort = splitListen(infra.value.httpListen)?.port
    if (httpPort && httpPort === adminParts.port) {
      return '管理面端口不能与 HTTP 数据面端口相同'
    }
    const httpsPort = splitListen(infra.value.httpsListen)?.port
    if (infra.value.httpsEnabled && httpsPort && httpsPort === adminParts.port) {
      return '管理面端口不能与 HTTPS 数据面端口相同'
    }

    const agentUrl = effectiveAgentUrl.value
    if (!agentUrl) {
      return '请填写控制面可达的 AGENT_URL；跨机部署请先填公网 IP，或选择「自定义管理面地址」'
    }
    if (!validAgentUrl(agentUrl)) {
      return 'AGENT_URL 必须是 http(s)://主机[:端口]，不能带路径或特殊字符'
    }
    const agent = parseHttpUrl(agentUrl)
    if (!agent) return 'AGENT_URL 格式无效'
    if (agent.port !== adminParts.port) {
      return `AGENT_URL 端口（${agent.port}）必须与 EDGE_ADMIN_LISTEN 端口（${adminParts.port}）一致`
    }
    if (agent.host === '0.0.0.0' || agent.host === '::') {
      return 'AGENT_URL 不能使用 0.0.0.0 / ::，控制面无法回调'
    }
    if (isLoopbackAddress(adminParts.host) && !isLoopbackAddress(agent.host)) {
      return '管理面只监听回环地址，但 AGENT_URL 使用非回环地址：控制面无法回调'
    }
    if (!isLoopbackAddress(adminParts.host) && isLoopbackAddress(agent.host)) {
      return 'AGENT_URL 指向回环地址，跨机控制面无法回调'
    }
    return ''
  }

  if (index === 1) {
    if (!Number(hw.value.cpuCores) || hw.value.cpuCores < 1 || hw.value.cpuCores > 128) {
      return 'CPU 核数需在 1–128 之间'
    }
    if (!Number(hw.value.memoryGb) || hw.value.memoryGb < 1 || hw.value.memoryGb > 512) {
      return '内存需在 1–512 GiB 之间'
    }
    if (Number(hw.value.diskGb) < 0 || Number(hw.value.diskGb) > 100_000) {
      return '磁盘容量需在 0–100000 GiB 之间'
    }
    if (Number(hw.value.bandwidthMbps) < 0 || Number(hw.value.bandwidthMbps) > 100_000) {
      return '出口带宽需在 0–100000 Mbps 之间'
    }
    if (!isValidListen(infra.value.httpListen)) {
      return 'EDGE_LISTEN 格式应为 IP/主机:端口，例如 0.0.0.0:80'
    }
    if (infra.value.httpsEnabled && !isValidListen(infra.value.httpsListen)) {
      return 'HTTPS 监听地址格式应为 IP/主机:端口，例如 0.0.0.0:443'
    }
    if (
      infra.value.httpsEnabled &&
      splitListen(infra.value.httpsListen)?.port === splitListen(infra.value.httpListen)?.port
    ) {
      return 'HTTPS 与 HTTP 监听端口不能相同'
    }
    const adminPort = splitListen(infra.value.adminListen)?.port
    if (splitListen(infra.value.httpListen)?.port === adminPort) {
      return 'HTTP 数据面端口不能与管理面端口相同'
    }
    if (infra.value.httpsEnabled && splitListen(infra.value.httpsListen)?.port === adminPort) {
      return 'HTTPS 数据面端口不能与管理面端口相同'
    }
    for (const value of [infra.value.redisUrl, infra.value.cacheRedisUrl]) {
      if (value.trim() && !/^rediss?:\/\//i.test(value.trim())) {
        return 'Redis 地址必须以 redis:// 或 rediss:// 开头'
      }
      if (/\s/.test(value)) return 'Redis 地址不能包含空白字符'
    }
    // The env file is unquoted (quoting would change the value), so a secret
    // containing whitespace, a quote or '#' would be parsed differently by
    // systemd/dotenvy than the operator expects.
    for (const [name, value] of [
      ['CHALLENGE_SECRET', infra.value.challengeSecret.trim()],
      ['WAF_RULEPACK_SECRET', infra.value.wafRulepackSecret.trim()],
    ] as const) {
      if (value && /[\s#'"]/.test(value)) {
        return `${name} 不能包含空白、引号或 #（EnvironmentFile 按字面解析）`
      }
    }
    if (
      infra.value.cacheBackend === 'redis' &&
      !infra.value.redisUrl.trim() &&
      !infra.value.cacheRedisUrl.trim()
    ) {
      return 'CACHE_BACKEND=redis 需要填写 REDIS_URL 或 CACHE_REDIS_URL；没有 Redis 请改回「按硬件自动」'
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

/**
 * Payload stored on the node so the detail drawer can rebuild the same file.
 *
 * Every value that changes the rendered `edge.env` must be here, otherwise the
 * drawer silently disagrees with the wizard.
 */
function currentProfile() {
  return {
    hardware: { ...hw.value },
    infra: {
      deployment: infra.value.deployment,
      httpListen: infra.value.httpListen.trim(),
      httpsEnabled: infra.value.httpsEnabled,
      httpsListen: infra.value.httpsListen.trim(),
      adminListen: infra.value.adminListen.trim(),
      agentUrl: effectiveAgentUrl.value,
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
      // The control plane stores this as the callback URL it will call. Sending
      // the derived value keeps the database, AGENT_URL and EDGE_ADMIN_LISTEN
      // in agreement from the first heartbeat.
      agent_url: effectiveAgentUrl.value,
      public_ip: form.value.public_ip.trim(),
      country: form.value.country.trim().toUpperCase() || 'CN',
      province: form.value.province.trim(),
      city: form.value.city.trim(),
      isp: form.value.isp.trim(),
      weight: Math.round(Number(form.value.weight) || 100),
      max_bandwidth_mbps: Math.round(Number(hw.value.bandwidthMbps) || 0),
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
 * Push the current hardware/network profile to the node.
 *
 * Only the profile and the derived callback URL are sent: identity fields stay
 * untouched, so a node that is already serving traffic cannot be renamed or
 * re-pointed by a late "next" click.
 */
async function syncProfile() {
  const id = created.value?.node?.id
  if (!id) return
  try {
    await api.put(`/api/v1/nodes/${id}`, {
      agent_url: effectiveAgentUrl.value,
      max_bandwidth_mbps: Math.round(Number(hw.value.bandwidthMbps) || 0),
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
  stepError.value = ''
  liveNode.value = null
  // Hand-tuned numbers belong to the node we just abandoned; the next machine
  // should start from its own recommendation. Shared secrets stay: they must
  // remain identical across the fleet.
  overrides.value = {
    workerThreads: undefined,
    memoryCacheMiB: undefined,
    largeCacheGiB: undefined,
  }
  const keep = {
    challengeSecret: infra.value.challengeSecret,
    wafRulepackSecret: infra.value.wafRulepackSecret,
    redisUrl: infra.value.redisUrl,
    cacheRedisUrl: infra.value.cacheRedisUrl,
  }
  hw.value = { ...EDGE_PROFILE_DEFAULTS.hardware }
  infra.value = { ...EDGE_PROFILE_DEFAULTS.infra, ...keep }
  form.value = {
    name: '',
    region: '',
    public_ip: '',
    country: 'CN',
    province: '',
    city: '',
    isp: '',
    weight: 100,
  }
  applyDeployment()
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

/* ---------------------------------------------------- derived callback pair */
.derived-box {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--bg);
}

.derived-title {
  font-size: 12.5px;
  color: var(--text-2);
}

.derived-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  font-size: 12.5px;
}

.derived-key {
  color: var(--text-3);
}

.derived-val {
  text-align: right;
  word-break: break-all;
}

.role-note {
  display: block;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-3);
}

.secret-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}

.secret-row .input {
  flex: 1;
  min-width: 160px;
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
  max-height: 220px;
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
