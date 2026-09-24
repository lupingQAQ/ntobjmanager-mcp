# Contributing

## 开发原则（本项目最高优先级约定）

1. **状态必须活在常驻引擎里** —— 任何需要跨调用存活的 .NET 对象
   （RpcServer / 连接的客户端 / vars）只放 `$RPCMCP`，禁止进程外重建
2. **转义边界不可破** —— 用户输入到 PowerShell 的唯一通道是
   `ps_str()`（单引号双写）或 JSON 字符串化；禁止任何字符串拼接进模板
3. **每个新工具必须有 audit.py 覆盖** —— 正常路径 + 错误路径 + 敌意输入，
   三套套件全绿是合并门槛
4. **破坏性操作必须显式 opt-in** —— 参考 `rpc_fuzz` 的 dry-run 默认
5. **诚实的能力边界** —— 做不到的写进 README 边界表，不夸大判定语义

## 提交规范

- 修复/裁决沿用 `R<n>` 编号并在 CHANGELOG.md 登记
- 新增工具须更新 ARCHITECTURE.md 与两份 README 的工具矩阵
- 运行产物（`output/`、`client_*.cs`、符号缓存）一律不提交

## 测试

```
python tests\smoke_test.py    # 17 项 —— 真实 stdio 全链路
python tests\var_test.py      # 10 项 —— store_as/__var__ 机制
python tests\audit.py         # 43 项 —— 边界 / 并发 / 引擎鲁棒性
```

## 分发注意

本仓库发布物不得包含：真实主机信息（用户名/本地路径）、
挖掘产物（inventory/审计日志）、未披露漏洞细节。
