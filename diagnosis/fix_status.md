# Record 校验修复状态（承接 `record_stage_analysis.md`）

> 状态：A/B/C/D/E（前半）已落地并通过离线回归。C 按用户“不脱敏（报告自看）”口径放宽为“身份标识可字面量、凭据仍拒”；D 按“XSS 要求放宽一点”完成后**进一步按用户要求开放 browser-only 报告准入**（纯客户端 sink 可无 HTTP packet 成报告）。

## 已落地

| 根因 | 修复内容 | 代码 |
|---|---|---|
| A 变量命名校验不对称 | `replayPlanError()` 现在校验 `save_json`/`save_headers` 键名：必须 `^[A-Z][A-Z0-9_]*$` 且不得复用算子变量；错误信息含具体键名 | `apps/worker/src/services/http-replay.ts`（`savedVariableError`）|
| B 大整数精度 | `replayPlanError()` 拒绝 `body_json` 中 `>2^53` 的整数（递归含嵌套），提示改为字符串或 `${VARIABLE}` | 同上（`unsafeIntegerLiteral`）|
| E（前半）review 校验不一致 | 因复核收集器 `exploit-review-collector.ts` 本就走 `replayPlanError()`，A/B 自动作用于“修订计划”，review 阶段即可拦下并回报 | 复用上两处 |
| C 过宽 secret 匹配（**用户已拍板：不脱敏**）| 断言里的**身份标识**（`$username`/`$email`，如 `cqpv8a`）不再与**凭据**（cookie/token/password）同罪：新增 `credentialCaptureRedactions()` 剔除身份类脱敏，仅保留凭据。三处 `configuredCaptureRedactions(...)` 定义点全部改为 `credentialCaptureRedactions(configuredCaptureRedactions(...))`，于是：(1) 计划校验不再因身份字面量拒收；(2) 报告投影（`attachHttpEvidence` 捕获请求/响应 + 浏览器证据文本）与 exploit 交付物不再把操作者账号掩成 `$username`；(3) 计划与 `reproduce.sh` 本就原样携带身份字面量。凭据类仍一律拒绝/掩码 | `apps/worker/src/services/http-evidence.ts`（`IDENTITY_REDACTION_PLACEHOLDERS`/`credentialCaptureRedactions`）、`apps/worker/src/temporal/activities.ts`（:1500/:2465/:2918 三处定义 + 4 处 secrets 站改用 `credentialReplayVariableValues`）|
| D XSS 回执过窄（**受控放宽**）| 新增 `assert_text`（selector+value）浏览器动作，`value` 必须恰为 `${XSS_MARKER}`；回执 `assertion_type` 扩展为 `dialog_exact | dom_marker`；DOM 断言走轮询 `innerText` 含 challenge；`hasTrustedBrowserReplay` 接受两类断言，且“双方均无 HTTP capture”时放行（`http_capture_ids` 一致校验保留）| `apps/worker/src/services/browser-replay.ts` |
| D 边界（**browser-only 报告准入，已开放**）| 纯客户端 sink（URL fragment / DOM 写入，payload 从不抵达服务端）没有 HTTP 影响可断言。现允许此类 finding **无任何 packet** 成报告，前提是其 host 浏览器回执通过同一套重校验（`hasTrustedBrowserReplay`，双方 capture 集合均为空）：(1) 采集端 XSS 在“有 browser 计划、无 HTTP 计划”时只跑浏览器腿；(2) `record_verification` 允许“有浏览器断言、零 capture”判 verified（`browserOnlyVerified`）；(3) 准入/白名单/证据挂载新增 browser-backed 通路（`loadBrowserBackedFindingIds`、`attachHttpEvidence` 省略 HTTP 段并改用浏览器证据段）| `apps/worker/src/collectors/record-collector.ts`、`apps/worker/src/services/http-evidence.ts`、`apps/worker/src/services/record-verification.ts`、`apps/worker/src/temporal/activities.ts` |

Python 运行器两处 `raise ValueError` 文案改为指明 `save_json`/`save_headers` 具体变量名（行为不变，仅报错更清晰）。

**安全性论证**：
- A 命中的计划原本在运行器里必然报错（不可能曾通过），故新检查不会把“曾通过的重放”变成失败；B 拒绝的是 JS 已四舍五入的 `body_json` 数字，即与作者意图不符的请求。
- C 只放宽“身份标识是否算泄漏/是否需掩码”；受保护资产仍是凭据，凭据一旦字面量出现依旧拒绝、在报告里依旧掩为 `$password`/`$totp` 等。代价：操作者账号名会留在报告/`reproduce.sh` 中（用户明确接受，报告仅自用）。
- D 放宽的是“触发信号的形态”，**不是**松掉可信性：仍要求 host 回执（`playwright-host-v1`）、plan 摘要匹配、`expected === observed`、challenge 正则、PNG magic+摘要、回执字节与证明逐字一致；DOM 断言仍必须断言 host 注入的同一 challenge。仅当**调用方也持有一致（空）capture 集合**时才以 browser-only 通过。
- D 边界放开后仍以回执为唯一信任锚：browser-only 只对 `XSS-*` 生效、只在其回执可重校验且 capture 集合为空时成立；任何被篡改的 `observed`、错误 plan 摘要、伪造截图或残留 capture 都会让其退回“missing complete associated HTTP packet”并被剔除。

**回归**：`scripts/test-record-plan-validation.mjs`（19 断言全过）、`scripts/test-xss-dom-receipt.mjs`（新增，10 断言全过）、`scripts/test-xss-browser-only-admission.mjs`（新增，16 断言全过：receipt 识别 / 准入 / 白名单 / 证据挂载 / 采集器 browser-only 判定 / 篡改回归）、`scripts/verify-http-evidence.mjs`（46 场景全过；其中“报告投影保留身份、掩码凭据”场景已按 C 更新）。
配套：`test-replay-variables.mjs`、`test-record-explore.mjs`、`test-report-admission.mjs` 仍全过；`test-browser-replay.mjs` 因本机无 Chromium 在 `browser_launch` 失败（对原始源码同样失败，与本次改动无关）。
`tsc -p apps/worker/tsconfig.json` 退出码 0；`biome check` 通过。

## 待讨论（未改动行为）

| 根因 | 提议 | 为什么要你拍板 |
|---|---|---|
| E（后半）| retry 失败回到“计划修复”而非一次判死；修订计划与 inventory 做 verb 交叉校验 | 属 Workflow/编排变更，影响面与成本更大 |
| B 次要 | 生成指南明确“大 ID 用字符串”；断言改“新增标记”相对断言，弃用绝对计数 | 指南/模板变更，需你确认口径 |
| 复测 | 对这 7 项按修正后的计划实跑 Record 回归 | 需真实目标/凭据，须由你安排环境 |
