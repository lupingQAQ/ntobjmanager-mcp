# NtObjectManager-MCP 架构（Architecture）

> 输入：AI agent 的 MCP 工具调用 → 输出：结构化 JSON（接口/端点/调用结果/挖掘报告）。
> 状态常驻、跨调用存活；全部用户输入经转义注入 PowerShell 模板。

## 模块图（唯一真相源）

```
server.py ───────────────── MCP 工具层（22 工具 + 审计日志装饰器 @tool）
  │  python 侧: 输入校验 / glob 展开 / 结果聚合 / 文件产物
  ▼
snippets.py ──────────────── PS 命令模板库（INIT/PARSE/CONNECT/CALL/…）
  │  @@TOKEN@@ 渲染 + ps_str() 单引号转义（'' 双写）
  ▼
ps_engine.py ─────────────── 常驻引擎（1 个 powershell.exe 进程 / MCP 会话）
  │  协议: base64(UTF-8 脚本) 一行 → stdout 回包 → __MCP_DONE__ 标记
  │  错误: __MCP_ERR__ 前缀行; 非终止错误走 stderr 缓冲
  │  超时: 杀进程 + EngineTimeoutError（状态丢失，错误信息提示重建）
  │  并发: 全局锁串行化（MCP 工具线程安全）
  ▼
wrapper.ps1 ──────────────── PS 侧循环（Invoke-Expression + 标记回写）
  │  状态: $RPCMCP = @{ Servers; Clients; vars; Order }
  │  辅助: __McpIfJson / __McpParamJson / __McpEpJson / __McpEpBinding / __McpCache
  ▼
NtObjectManager / NtCoreLib
  ├─ Get-RpcServer(-SymbolPath)      PE 静态解析（NDR / context handle / strict）
  ├─ Get-RpcEndpoint                 EPM 查询（本地/远程/-FindAlpcPort）
  ├─ Get-RpcClient + Connect-RpcClient   内存编译客户端 + 连接（有状态核心）
  ├─ Format-RpcClient                C# 客户端源码导出
  └─ ALPC / 计划任务 / SD 辅助 cmdlet
```

## 有状态模型

```
$RPCMCP.Servers[key]  = @{ key; server=RpcServer; file }     # 解析缓存（淘汰上限 150, FIFO: Order）
$RPCMCP.Clients[sess] = @{ client; key; interface; binding; connected_at; vars }
$RPCMCP.Clients[sess].vars[name] = <任意 .NET 对象>            # store_as 存入, {"__var__"} 取出
```

- **vars 是跨调用对象通道**：producer 返回的 context handle / rpc_new_struct 构造的
  NDR 结构以原始对象传递给后续调用，不经 JSON 序列化往返 —— 类型混淆链的前提。
- 缓存淘汰不触碰 Clients（客户端对象独立于 Servers 存活；opnum 查找做了缺失容错）。

## rpc_call 参数编组（PS 5.1 两个坑的沉淀）

```
args_json ──ConvertFrom-Json──▶ 逐元素判定:
   {"__var__": n}  → $entry.vars[n]          （原始对象直传）
   {"__ps__": e}   → Invoke-Expression e      （表达式求值）
   基本类型         → .PSObject.BaseObject     （拆 PSObject 包装）
                                                ↓
                          MethodInfo.Invoke(client, object[])   ← DefaultBinder 原语转换
```

- **坑 1**：`@(ConvertFrom-Json $aj)` 在 PS 5.1 会把 JSON 数组**多包一层**
  （所有非空参数变 `Object[]`，`__var__`/`__ps__` 分支永不命中）。
  修复 = 变量中转 `$parsed = ConvertFrom-Json $aj; $rawArgs = @($parsed)`（R4）。
- **坑 2**：方法名消歧 —— 生成器对重名过程用 `_<procnum>` 后缀，
  opnum 映射必须后缀正则优先于名字表（R8）。

## 关键设计裁决

| 裁决 | 原因 |
|---|---|
| 常驻单进程 + 标记协议 | RPC 客户端对象无法跨进程迁移；通用 PS MCP 无状态，认证握手/context 链全断 |
| base64 传输命令 | 彻底绕开 stdin 编码/引号注入问题；输出侧强制 UTF-8 |
| 反射调用而非拼接表达式 | 杜绝方法名/参数注入；`IsSpecialName` 过滤属性访问器（`get_New` 事故，R3） |
| 结果一律 `ConvertTo-Json -Compress` | 单行输出防 `Out-String` 折行破坏 JSON |
| store_as / `__var__` | context handle 序列化即失真；对象直传是混淆链唯一可行通道（R5） |
| fuzz 默认 dry-run | CVE-2025-26651 式"默认值打崩 LSM"在本机重演风险；执行需显式确认 |
| 不提供 raw shell 工具 | 攻击面收敛：每个工具只暴露白名单化的 PS 片段 |
| ETW 失败必须显性报错 | 非管理员 logman 失败曾静默返回 ok 形状 0 事件（R6） |
| 扫描器 verdict 措辞降级 | "多分组"≠多类型（XactSrv 单一打印机句柄仍报 HIGH 的误报事故，R9） |
| 每调用写审计日志 | agent 持有 RCE 级能力，可观测性是底线 |

## 测试架构

```
tests/smoke_test.py  17 项  真实 MCP stdio 客户端全链路（解析→连接→调用→断开）
tests/var_test.py    10 项  store_as/__var__ 机制（DateTime 伪客户端，零真实 RPC 风险）
tests/audit.py       43 项  A 协议 schema / B 输入校验 / C 敌意路径 / D 非 PE /
                            E 状态压力 / F 并发 / G 参数编组（含真实活体调用）/
                            H 未测工具 / J 新工具 / I 引擎超时杀死重启
tests/hunt*.py       4 个实战脚本（安全策略：只读侦察 + 无害探针）
```

已知边界（登记，非阻断）：符号解析依赖 symsrv 链路（本机未生效则回退启发式名）；
ETW/ALPC-SD 需管理员；流氓 RPC 托管受限于 NtObjectManager 2.0.1 无 server builder。
