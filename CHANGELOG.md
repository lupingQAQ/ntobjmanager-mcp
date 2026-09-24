# Changelog（设计裁决编号史 R1–R12）

历史轮次的全部修复与裁决，按主题归组。编号保留可追溯性；
复现证据见 tests/ 三套套件（smoke 17 / var 10 / audit 43）。

## 引擎与协议
- **R1** 常驻单进程 + base64/`__MCP_DONE__` 标记协议（跨调用状态的唯一载体）
- **R2** `$RPCMCP` 状态哈希（Servers/Clients/vars）+ 解析缓存（上限 150，FIFO 淘汰）
- **R11** 每调用审计日志（`@tool` 装饰器 → `output/mcp_audit.log`）

## 调用与编组（两个 PS 5.1 实锤坑）
- **R3** 反射调用 + `IsSpecialName` 过滤（`rpc_methods` 曾列出 `get_New` 属性访问器）
- **R4** 参数编组嵌套修复：`@(ConvertFrom-Json …)` 多包一层 → 全部参数变 `Object[]`，
  `__ps__`/`__var__` 分支永不命中（var_test 首次真实传参才暴露；改变量中转）
- **R5** `store_as` / `{"__var__"}` 原始对象通道（context handle 链式传递的前提）
- **R8** 重名过程 opnum 映射：生成器 `_<procnum>` 后缀 → 正则优先于名字表
  （srvsvc 全部过程叫 `SvchostPushServiceGlobals` 时映射全错的事故）
- **R10** 错误响应补 `ok:false`（一致性）

## 方法论工具与安全
- **R6** ETW 非管理员静默失败 → 显式报 `logman: Access is denied` + 提示提权
- **R7** 移除 `-SymSrvFallback`（该参数组合静默返回 0 个服务器）
- **R9** 扫描器措辞降级："多分组" ≠ 多类型句柄（XactSrv 单一打印机句柄仍报
  HIGH 的误报事故；methodology_note 加入警示与 RE 验证指引）
- **R12** `rpc_fuzz` 默认 dry-run；`rpc_alpc_squat` 端口名白名单 + finally 释放

## 实战沉淀（dogfood 一轮 + 深挖一轮）
- XactSrv（`98716d03`）识别：UUID 溯源 + 实测 ACCESS_DENIED —— 授权闸门有效
- ssdpsrv 全 strict —— CVE-2025-48815 在当前构建已修补
- 51 模块广撒网：6 个 HIGH 全为"单 producer→多 consumer"；NDR 层类型判定
  边界已探明并写入文档
