<template>
  <div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.25rem;">
      <p class="muted" style="margin:0;">管理 CDN 项目与租户空间</p>
      <button class="btn">新建项目</button>
    </div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>项目名称</th>
            <th>域名数</th>
            <th>创建时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Demo Project</td>
            <td>1</td>
            <td class="muted">2026-10-23</td>
            <td><button class="btn btn-ghost">管理</button></td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
