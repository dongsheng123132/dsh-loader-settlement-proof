# dsh-loader-settlement-proof

作者 / 维护者：贺去病（贺方升 / Dosen）· [hequbing.com](https://www.hequbing.com)

面向 DeepSeek Harness Loader 结算记录的离线证据层。它对固定、无正文的 receipt 验证：DSH revision/Loader contract 绑定，`declared → resolved → loaded → activated` 顺序，必需条目激活，inject 闭包，以及工具名和 schema SHA-256。

它不是第二个 Loader：不导入、不启动、不重载、不切换任何被记录插件。DSH 官方 `app-boot` 负责实时失败闭合；`dsh-reloader` 负责重启，`dsh-builtin-toggles` 负责有限 UI 切换，`dsh-profile-lock-proof` 负责安装闭包，Awesome runtime matrix 负责真实跨平台启动。本插件只把 producer 提供的脱敏结算记录变成可复核、内容寻址的判决。

DSH/CLI 只读显式 workspace-relative 文件，只向显式 artifactDir 原子发布并回读。MCP 仅接收有界内联 JSON，不读文件、不联网、不执行命令。任何 secret、token、raw output、日志正文、prompt、stack 等形字段都会被递归拒绝。

```sh
npm test
npm run check
npm run smoke:plugin
npm run smoke:mcp
```

`verified` 只表示 receipt 与显式 policy 内部一致，不是插件安全认证，也不能证明 producer 如实观察了真实 Loader。
