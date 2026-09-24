# Security Policy / 安全策略

## 适用边界（Authorized Use Only）

NtObjectManager-MCP 是**防御性安全研究工具**：用于在自有/授权环境上
评估 Windows RPC 攻击面，先于攻击者完成修复评估。

**禁止**将本工具用于：
- 未经书面授权的目标系统
- 实际入侵、数据窃取、破坏
- 对生产环境或日常主机执行 `rpc_call` / `rpc_fuzz(dry_run=False)`（可致服务崩溃）

## 运行环境要求

- **隔离虚拟机优先**：快照回滚是 RPC 研究的标准工作流
- ETW 追踪（`rpc_etw_unreachable`）与 ALPC SDDL 读取需管理员权限
- 接入 agent 前确认 MCP 配置只在可信主机范围内启用

## 负责任披露（Responsible Disclosure）

通过本工具发现新漏洞时：
1. 先向 Microsoft Security Response Center（MSRC）披露，给 90 天修复窗口
2. 未经许可不得公开未修复细节
3. 里程碑类发现建议同步 CVE / 编号机构

## 报告安全问题

对本工具自身的安全 issue（如注入、转义绕过）：开 private security advisory。
转义边界是核心攻击面 —— 任何用户输入到达 PowerShell 的路径必须经过
`ps_str()`（单引号双写）或 JSON 字符串化。

## 工具内置防护

- 全部用户输入经 `@@TOKEN@@` 渲染 + 单引号转义注入 PS 模板，无字符串拼接
- `rpc_fuzz` 默认 dry-run（仅计划不执行），执行需显式 `dry_run=False`
- 不提供任意 shell / 任意脚本工具；每个工具只暴露白名单化 PS 片段
- 每次工具调用追加审计日志（`output/mcp_audit.log`），agent 行为可回溯
- 命令超时自动杀引擎并显式报状态丢失（防挂死且不静默）
- `rpc_alpc_squat` 限制简单端口名（拒绝路径型输入）并在 finally 中释放端口
