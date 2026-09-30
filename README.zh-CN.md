# 🛰️ NtObjectManager-MCP

### 有状态 Windows RPC 研究 MCP —— 2024–2026 公开 CVE 方法论一键化

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/windows-server/administration/windows-commands/powershell)
[![MCP](https://img.shields.io/badge/MCP-24%20tools-purple)](https://modelcontextprotocol.io)

🌐 **[English](README.md)**

---

## 什么是 NtObjectManager-MCP？

一个让 AI agent 获得**有状态、可实战**的 Windows RPC 攻击面研究能力的 MCP 服务器，
底层封装 James Forshaw 的
[NtObjectManager](https://www.powershellgallery.com/packages/NtObjectManager)（NtCoreLib）。

通用 PowerShell MCP 做不到、而本项目存在的三个理由：

1. **有状态 RPC 连接** —— 常驻 PowerShell 引擎让解析出的 `RpcServer` 对象与
   *已连接的 RPC 客户端*跨工具调用存活：`rpc_connect` 一次，`rpc_call` 多次
   （认证握手、context handle 链、会话变量全保留）。
2. **CVE 方法论固化为固定工具** —— 2024–2026 公开研究的标准挖掘工作流一键调用，
   不靠提示词工程。
3. **lab VM 内有状态执行** —— 把同一“单引擎”原则用到 guest：`rpc_vm_exec` 通过单个常驻
   guest runspace 让变量与已连 RPC 客户端跨调用存活，绝不每调用新开 shell
   （vmrun 回退标注 `stateful: false`）。

```
┌────────────────────────────────────────────────────────────────────┐
│  AI Agent（Claude Code / OpenCode / 任意 MCP 客户端）               │
│      │  MCP（stdio，24 个工具）                                    │
│      ▼                                                             │
│  server.py ── snippets.py（PS 模板，@@TOKEN@@ 渲染 + ps_str 转义）  │
│      │                                                             │
│      ▼                                                             │
│  ps_engine.py ── 常驻 powershell.exe（base64 + __MCP_DONE__ 协议）  │
│      │            状态: $RPCMCP = @{ Servers; Clients; vars }      │
│      ▼                                                             │
│  NtObjectManager / NtCoreLib ──► RPC 运行时（ALPC / 管道 / TCP）    │
└────────────────────────────────────────────────────────────────────┘
```

## 工具矩阵（24 个）

### 核心有状态管线

| 工具 | 用途 |
|------|------|
| `rpc_parse(file, symbol_path?)` | 解析 PE 内嵌 RPC 服务器并缓存（键 `file_N`） |
| `rpc_state()` | 缓存服务器 + 活跃会话 |
| `rpc_get_interface(key)` | 过程、NDR 参数、context handle 及 strict 标记 |
| `rpc_query_endpoints(ifid?, search_binding?, find_alpc_port?)` | EPM 查询（本地**或远程**） |
| `rpc_running_servers(pid?/service?)` | 运行中进程/服务枚举 |
| `rpc_connect(session, key, binding?, auth?)` | 生成并**连接**客户端（有状态） |
| `rpc_methods(session)` | 方法签名，**带 opnum 映射** |
| `rpc_call(session, method, args_json, store_as?)` | 反射调用；`{"__var__"}` 直传已存对象 |
| `rpc_disconnect(session)` | 断开会话 |

### VM 实验桥（有状态 guest 执行）

| 工具 | 用途 |
|------|------|
| `rpc_vm_exec(ps, timeout?, vm?)` | 在实验 VM 内运行 PowerShell；跨调用保持状态（常驻 guest runspace） |
| `rpc_vm_start_listener(vm?)` | 部署/启动常驻 guest HTTP 引擎（`vm_listener.ps1`） |

### 2024–2026 CVE 方法论工具

| 工具 | 方法论来源 |
|------|-----------|
| `rpc_scan_context_handles(paths)` | context handle 类型混淆 —— CVE-2025-48815 模式（whereisk0shl 2026） |
| `rpc_inventory(paths?, limit?)` | 攻击面清单 + EPM 交叉 —— MS-RPC-Fuzzer 第一阶段（CVE-2025-26651） |
| `rpc_fuzz(session, dry_run=True)` | 原始参数默认值模糊测试，ok/拒绝/错误三分类 —— **默认 dry-run 安全** |
| `rpc_find_hijackable()` | 停止服务的未注册接口 —— EPM 投毒 / RPC-Racer（CVE-2025-49760/59200/59230） |
| `rpc_etw_unreachable(duration, trigger_script?)` | 找"调用已死服务端"的客户端 —— PhantomRPC（Kaspersky 2026），需管理员 |
| `rpc_interface_security(key)` | ALPC SD / 匿名 ACE 审计 —— MS-NRPC 空会话（Securelist 2025） |
| `rpc_decode_flags(flags)` | `RpcServerRegisterIf3` 标志位解码 |
| `rpc_format_client(key)` | 导出生成的 C# 客户端源码（离线 grep 工作流） |
| `rpc_new_struct(session, type, store_as)` | 构造 NDR 复杂类型存为会话变量 |
| `rpc_alpc_squat(name, duration)` | ALPC 端口抢占 + 连接捕获（竞态验证原语） |
| `rpc_accessible_tasks()` | 用户可启动任务（Dark-Elevator 链素材，CVE-2026-66804 模式） |
| `rpc_vars` / `rpc_clear_cache` | 会话变量与缓存管理（淘汰上限 150） |

每次工具调用追加记录到 `output/mcp_audit.log`。

## 实战验证（真实机器完整挖掘一轮）

| 候选 | 结果 |
|------|------|
| `srvsvc.dll 98716d03…`（HIGH） | 识别为 **XactSrv**（XsOpenPrinter/XsClosePrinter/XsAddJob/XsScheduleJob）—— 单一打印机句柄类型；实测：非管理员可连接但 `XsOpenPrinter` → **ACCESS_DENIED**（授权闸门有效）。扫描器误报模式已文档化 |
| `ssdpsrv.dll`（CVE-2025-48815 原型） | 20 个 context handle **全部 strict** —— 当前构建已修补 |
| 51 模块广撒网 | 31 项发现、6 个 HIGH，全部"单 producer→多 consumer"；NDR 层无法证明多*类型*句柄（需逆向） |
| EPM 劫持面 | 10 个停止服务的未注册接口（AppIDSvc、ClipSVC、dcsvc…） |
| 任务链 | 盘点 44 个用户可启动的 SYSTEM 任务 |
| **判定** | 受测主机无可确认可利用漏洞 —— 每步有证据 |

## 🚀 快速开始

```powershell
# 1) 前置（一次性）
Install-Module NtObjectManager -Scope CurrentUser -Force
pip install -r requirements.txt            # mcp>=1.2.0（兼容 1.x / 2.x）

# 2) 验证 —— 三套测试全绿
python tests\smoke_test.py                 # 17 项（真实 MCP stdio 全链路）
python tests\var_test.py                   # 10 项（store_as / __var__ 机制）
python tests\audit.py                      # 43 项（边界输入、敌意路径、并发）

# 3) 启动服务器
python server.py                           # stdio MCP
```

**Claude Code：**

```bash
claude mcp add ntobjectmanager-rpc -- python C:\path\to\ntobjmanager-mcp\server.py
```

**任意 MCP 客户端**（如 OpenCode `opencode.json`）：

```json
{
  "mcp": {
    "ntobjectmanager-rpc": {
      "type": "local",
      "command": ["python", "C:\\path\\to\\ntobjmanager-mcp\\server.py"],
      "enabled": true
    }
  }
}
```

## 示例：context handle 类型混淆（CVE-2025-48815 模式）

```
1. rpc_parse  C:\Windows\System32\target.dll  [可选 symbol_path]
2. rpc_scan_context_handles ["C:\\Windows\\System32\\target.dll"]
3. rpc_get_interface target_0                 → producer（[out] ctx）/ consumer（[in] ctx）配对
4. rpc_connect s1 target_0                    → 经 EPM 自动发现绑定
5. rpc_methods s1                            → 带 opnum 的方法签名
6. rpc_call s1 类XsOpenPrinter参数 store_as="h"   → 保留原始句柄对象
7. rpc_call s1 类XsClosePrinter [{"__var__":"h"}] → 喂给另一种类型
```

`store_as` / `{"__var__"}` 是核心链式原语：RPC 返回对象在调用间流转
**不经序列化往返** —— 正是 producer→consumer 句柄混淆测试所需。

## 📁 项目结构

```
ntobjmanager-mcp/
├── server.py            # 24 个 MCP 工具 + 审计日志装饰器
├── snippets.py          # PowerShell 模板（@@TOKEN@@ 渲染 + ps_str 转义）
├── ps_engine.py         # 常驻引擎：base64 命令 + __MCP_DONE__ 标记，超时处理
├── wrapper.ps1          # PS 侧循环（状态存于 $RPCMCP）
├── vm_listener.ps1      # 常驻 guest HTTP 桥（有状态 VM 执行）
├── tests/
│   ├── smoke_test.py    # 17 项 —— stdio 端到端
│   ├── var_test.py      # 10 项 —— store_as/__var__ 对象直传
│   ├── audit.py         # 43 项 —— 敌意输入、并发、引擎杀死重启
│   ├── hunt.py          # 完整 dogfood 挖掘轮（安全策略）
│   ├── hunt2_static.py  # 深挖：符号 + producer/consumer 映射
│   ├── hunt2_wide.py    # 51 模块广撒网
│   └── hunt2_probe.py   # 安全运行时探针（暴露面 / 任务交集）
├── ARCHITECTURE.md      # 引擎协议 + 设计裁决
├── CHANGELOG.md         # 裁决史（R1–R13）
├── SECURITY.md          # 授权使用 + MSRC 披露
├── CONTRIBUTING.md      # 开发不变式
└── LICENSE              # MIT
```

## 🛡️ 诚实的能力边界

| 主张 | 状态 |
|------|------|
| 客户端跨工具调用有状态 | 是 —— 常驻引擎 + `$RPCMCP` |
| lab VM 内有状态执行 | 是 —— 单个常驻 guest runspace（`rpc_vm_exec`）；vmrun 回退无状态 |
| context handle 链式传递（producer→consumer） | 是 —— `store_as` / `__var__` 原始对象直传 |
| 自动确认类型混淆 | **否** —— NDR 无法证明句柄*类型*差异；需逆向验证（见 XactSrv 案例） |
| 完整流氓 RPC 托管 | **否** —— NtObjectManager 2.0.1 无 server builder；`rpc_alpc_squat` 只覆盖竞态捕获 |
| ETW 追踪 / ALPC SDDL | 需**管理员**（logman / SeDebugPrivilege） |
| 符号解析过程名 | 依环境而定（symsrv 链路）；否则启发式回退名 |
| 非 Windows PS 5.1 环境 | 未测（pwsh 7 未支持） |

## 📖 文档

- [ARCHITECTURE.md](ARCHITECTURE.md) —— 引擎协议、状态模型、设计裁决
- [CHANGELOG.md](CHANGELOG.md) —— R1–R13 裁决史（含两个 PS 5.1 编组 bug）
- [SECURITY.md](SECURITY.md) —— 授权使用、VM 隔离、MSRC 披露
- [CONTRIBUTING.md](CONTRIBUTING.md) —— 开发不变式与测试要求

## ⚠️ 免责声明

仅用于**合法安全研究、教学与授权测试**。
`rpc_call` 会真实调用 RPC 方法、可能崩服务 —— 请在**隔离虚拟机**中运行，
切勿对生产或日常主机使用。经本工具发现的漏洞须遵循负责任披露（MSRC）。

## 📄 许可证

[MIT](LICENSE) —— Copyright (c) 2026 ntobjmanager-mcp Contributors
