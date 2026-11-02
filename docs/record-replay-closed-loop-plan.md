# Record 复现闭环改造计划

2026-11-02 后续会话已确认最终失败策略：跳过仍复现失败的漏洞，生成其余已验证漏洞的报告。下文以此策略为准；失败项保留原始记录与审计，不当作 FP。

## 1. 目标

Exploit 阶段标记为 `exploited` 的 finding，必须由 Record 阶段独立复现并采集到可复核证据，才能进入最终报告。Record 不再把验证失败项转交人工复核。

核心流程：

```text
record
  -> record-expansion
  -> 聚合全部 replay 失败项
  -> record-failure-review（按漏洞类别交回 vuln-exploit 复审）
       -> FP：从完整 finding 链路删除
       -> 非 FP：生成修订后的 replay plan、变量刷新要求和操作指导
  -> record-retry（只重试失败 finding）
       -> 成功：保存新鲜证据，覆盖旧 failed 结果
       -> 仍失败：写入结构化失败审计日志，并从报告中明确排除
  -> 完成失败审计与报告准入清单后进入 report:assemble，仅包含 verified 项
```

## 2. 不可放宽的约束

1. Exploit 负责发现和验证漏洞，Record 负责独立复现与证据采集；两者职责不合并。
2. Record 的 finding 状态只允许 `verified` 或 `failed`，不得出现 `manual_review`。
3. 删除 `pending_manual_verification.md` 及所有转人工路径。
4. 每个 `verified` finding 必须至少有一个完整 HTTP 请求/响应包。
5. XSS 除完整 HTTP 包外，还必须包含实际 JavaScript 执行证据；只有 HTTP 反射不算验证成功。
6. `capture_http_request` 等诊断 capture 不能单独授予 `verified`。
7. 报告仅准入有 `verified` verdict、完整 HTTP 包及必要 XSS 执行证据的 finding。最终未通过项必须写失败审计及 `record_report_exclusions.json`，保留原始 collector，不得静默过滤；已准入项之后丢失证据仍应阻断报告。
8. 复审只有在确认 finding 为 FP 时才能删除；非 FP 必须修订计划并交给 Record 重试。
9. 本流程允许一轮批量复审和一轮 retry。每条 finding 每轮最多三次 HTTP replay（含首次）和两次变量修正。retry 仍失败后记录结构化失败事件并排除该项，不自动无限循环，也不转人工验证。
10. Record 重试必须获取新鲜、有效的变量取值，不得把 Exploit 阶段可能已过期的秘密值当作无条件有效值。
11. 秘密值不得写入 deliverables、checkpoint 或普通日志；只能保存在 workspace 私有 scratchpad 的 `0600` 文件中。
12. `BASE_URL` 只能来自主机配置，Exploit/Record agent 不得覆盖。

## 3. 阶段与工作流改造

### 3.1 新增阶段

在 `apps/worker/src/types/post-exploitation.ts` 的 `POST_EXPLOITATION_STAGES` 中加入：

- `record-failure-review`：离线复审，不访问目标系统。
- `record-retry`：访问目标系统，按修订后的计划重试失败 finding。

在 `apps/worker/src/services/post-exploitation.ts` 中将 `record-retry` 加入 `TARGET_SIDE_EFFECT_STAGES`；`record-failure-review` 不加入。

### 3.2 Workflow 接线

修改 `apps/worker/src/temporal/workflows.ts`：

- `record-expansion` 完成后不再直接进入 `report:assemble`。
- 先运行失败聚合，再运行 `record-failure-review`。
- 复审结果存在非 FP 重试项时运行 `record-retry`。
- retry 完成后再次核对全部 finding 的最终 verdict。
- 最终生成 verified 允许列表及失败排除清单，然后组装其余已验证 finding。
- 最终失败项写入 `record-verification-failures.jsonl` 及 `record_report_exclusions.json`，保留原始记录；其余已验证 finding 继续进入报告。

### 3.3 Activity 注册

同步修改：

- `apps/worker/src/temporal/activities.ts` 的 `runPostExploitationStage` switch。
- `apps/worker/src/temporal/worker.ts` 的 activity 名称列表和实现注册（若实现为独立 activity）。

优先复用现有 `runPostExploitationStage` 机制，避免新增不必要的 activity 面。

## 4. 数据结构与数据契约

### 4.1 Record verdict

`apps/worker/src/collectors/record-collector.ts` 的 `RecordVerdict.status` 改为：

```ts
type RecordVerificationStatus = 'verified' | 'failed';
```

失败诊断至少包含：

- `failure_kind`
- `error`
- `attempts`
- `partial_capture_ids`
- `variable_diagnostics`
- `record_log_path`
- `stage`

Verdict 合并规则：

- 按 `finding_id` 合并，不按数组位置合并。
- 同一 finding 成功结果不得被后续失败降级。
- retry 成功必须覆盖该 finding 旧的 `failed` 结果。
- expansion 产生重复 finding 时必须去重。
- agent 未提交 verdict 的 finding 自动记为 `failed`，并附原因。

### 4.2 失败聚合文件

生成 `record-failures.json`，按 finding 保存：

- finding 基本信息、漏洞类别、标题和严重性。
- source collector entry 与 renumbered collector entry 引用。
- Exploit entry、Exploit 日志路径、原 replay plan 和变量需求。
- Record 各次尝试、失败类型、错误、部分 capture、变量诊断和日志路径。
- 已有证据、缺失证据和失败来源（record / expansion / retry）。

该文件同时作为 `vuln-exploit` 复审输入和最终审计输入。

### 4.3 复审输出

新增专用 review collector/tool，输出 `exploit_review_<class>.json`。不得复用 `add_exploit`，避免同一 finding 再次作为新漏洞提交。

每个 finding 的输出：

```json
{
  "finding_id": "AUTH-02",
  "verdict": "false_positive | retry",
  "reason": "判定依据",
  "revised_http_replay": {},
  "variable_requirements": {},
  "record_instructions": [],
  "expected_evidence": {}
}
```

FP 结果必须同步维护：

- collector finding 集合。
- 队列和 renumber map。
- Record verdict 与证据引用。
- 报告输入引用。

删除 FP 时不得重新运行严格 renumber，以免改变其余 finding 的稳定 ID 和引用。

### 4.4 最终失败审计

生成 `record-verification-failures.jsonl`，每个仍失败的 finding 一行，至少包括：

- 时间、run ID、finding ID、漏洞类别。
- Record 总尝试次数和最后一次失败诊断。
- 复审 verdict 与复审原因。
- 原/修订 replay plan 摘要。
- Record/Exploit 日志路径。
- `report_blocked: false`、`report_excluded: true`。

该日志是失败事件的最终记录。此类 finding 不进入报告，其余通过准入的 finding 可以生成报告。

## 5. 变量与 HTTP Replay 能力

### 5.1 变量模型

扩展 `apps/worker/src/services/replay-variables.ts`，兼容旧字符串 map，并支持结构化变量：

```json
{
  "TOKEN": "legacy-string",
  "OTP": {
    "value": "JBSWY3DPEHPK3PXP",
    "kind": "totp",
    "refresh": "each_attempt"
  },
  "SESSION": {
    "kind": "response_extract",
    "source_finding": "AUTH-01",
    "pointer": "data.token",
    "ttl_seconds": 600
  }
}
```

需要支持：

- `static` / 旧字符串值。
- `totp`：每次需要时生成当前六位 TOTP，不能直接发送 secret。
- `response_extract`：从指定 finding 的响应按 JSON pointer 提取。
- `refresh: each_attempt | on_ttl_expiry`。
- `ttl_seconds` 与过期检测。
- 缺失、过期、提取失败时的结构化变量诊断。

统一 `BASE_URL` 来源：host 配置注入；缺失变量检查与 loader 必须采用同一规则，不能出现“默认可用但保存时拒绝”的矛盾。

所有秘密值只落在私有 scratchpad 的 `0600` 文件；deliverables/checkpoint 只记录变量名、来源、刷新策略和非敏感状态。

### 5.2 Replay 执行器

扩展 `apps/worker/src/services/http-replay.ts`：

- 执行前解析并刷新变量，retry 前重新评估 TTL 和 `each_attempt` 变量。
- 支持 setup/cleanup 命令或请求，确保派生文件、临时目录和测试对象被正确清理。
- 支持 response extract，并保留提取失败的明确诊断。
- 保留空 header，使用可被 curl 正确发送的形式。
- multipart 由 curl `--form` 生成 boundary；禁止手写 `boundary` 与自动 `Content-Type` 冲突。
- 每个执行步骤都必须有完整 trace；任一步骤缺失请求或响应即判定失败。
- 成功的 Record capture 必须是可归属到 finding 的完整 HTTP 包，诊断 capture 不能替代。

## 6. Record 验证规则

### 6.1 普通漏洞

`verified` 必须满足：

- 对应 finding 的 replay 执行成功。
- 至少一个完整 HTTP request/response packet。
- packet 与 finding、replay attempt 和 capture ID 正确关联。

### 6.2 XSS

`verified` 必须同时满足：

- 完整 HTTP request/response packet。
- 浏览器实际执行 JavaScript 的断言证据（例如 marker、dialog 或等价可信执行观察）。

只有响应反射、DOM 中出现 payload、或 browser-only 断言，均不能单独授予 `verified`。

## 7. 失败复审与重试

### 7.1 批量复审

`record` 和 `record-expansion` 结束后统一聚合失败项，按漏洞类别交给现有 `<class>-exploit` agent 能力复审。复审输入必须同时包含：

- 本轮 `record-failures.json`。
- 上一轮 Exploit entry、replay plan 和完整 Exploit 日志。
- Record 每次尝试的日志、变量诊断和部分 capture。

复审目标：

- 找到真实根因：过期变量、提取错误、header/multipart 问题、setup/cleanup 缺失、错误断言、计划本身错误或 finding 为 FP。
- FP：给出可审计理由并删除。
- 非 FP：生成新的 replay plan、变量刷新策略、Record 操作指导和 expected evidence。

### 7.2 Record retry

`record-retry` 只加载失败 finding，不重跑全部已验证项。执行要求：

- 应用复审给出的新 plan 和变量策略。
- 在每次 attempt 前刷新必要变量。
- 从日志定位并修复可修正的执行问题。
- 成功项生成新鲜证据并覆盖旧 failed verdict。
- 失败项累积 attempts 和诊断，进入最终失败审计。

### 7.3 终止条件

一轮 retry 后：

- 非 FP finding 全部 `verified`：进入报告。
- 仍有失败：写 `record-verification-failures.jsonl` 和排除清单，生成其余已验证 finding 的报告。
- 不存在任何转人工分支。

## 8. 报告准入

修改 `apps/worker/src/temporal/activities.ts` 的报告准入逻辑：最终失败项显式审计并排除；禁止无审计的静默过滤。

准入检查：

1. Exploit 标记为 `exploited` 且未被复审为 FP 的 finding，必须存在 `verified` verdict。
2. 每个 `verified` finding 必须关联至少一个完整 HTTP packet。
3. XSS finding 必须同时关联 JavaScript 执行证据。
4. 最终复核时任一条件不满足：写最终失败审计及排除清单；报告阶段复检时，未在清单中排除的 finding 若缺失证据，抛出不可重试的 `RecordVerificationError`。
5. 报告只包含通过上述检查的 finding；FP 及最终未通过项不进入报告。保留未通过项的原始 collector、证据及重放历史。

## 9. 提示词、文档与路径

需要整体更新：

- `apps/worker/prompts/record.txt`
- 新增/更新 failure-review 与 retry 专用提示词。
- `apps/worker/prompts/shared/exploitation/_http-capture-and-replay.txt`
- `docs/http-evidence.md`
- `apps/worker/src/services/agent-git-paths.ts`

提示词必须明确：

- Exploit 交接时提供所有必要变量和刷新信息；对可能过期的值标明获取/刷新方式。
- Record 不得猜测缺失变量，不得把失败转人工。
- Record 失败后先读日志定位根因并修复执行计划。
- retry 只处理失败项。
- FP 只能由复审确认。
- XSS 的最终证据必须同时含 HTTP packet 和 JS 执行证据。

从所有代码、提示词、文档、测试和产物路径中删除：

- `manual_review`
- `pending_manual_verification.md`
- “待人工复核”相关文案

`agent-git-paths.ts` 删除人工复核文件，加入：

- `record-failures.json`
- `exploit_review_<class>.json`
- retry 结果与 `record-verification-failures.jsonl`

确保 Temporal resume checkpoint 覆盖新增阶段和产物，恢复运行不会跳过复审/retry，也不会使用旧失败 verdict 误判成功。

## 10. 测试与验收

### 10.1 自动化测试

- 更新 `scripts/verify-http-evidence.mjs`：删除 `manual_review` 预期，加入 `failed`、XSS 双证据、packet 关联和 fail-closed 用例。
- 更新 `scripts/test-record-explore.mjs`：覆盖 retry 只处理失败项、成功覆盖 failed、重复 finding 去重。
- 更新 `scripts/test-report-admission.mjs`：缺 verdict、缺 HTTP packet、XSS 缺 JS 证据均拒绝准入；最终失败项有审计排除后，其余 verified 项可生成报告；FP 不阻断。
- 增加变量测试：旧字符串兼容、TOTP、TTL、response extract、缺失/过期诊断、`BASE_URL` 唯一来源。
- 增加 replay 测试：空 header、multipart boundary、setup/cleanup、每个步骤完整 trace。
- 增加复审测试：FP 删除完整链路一致；非 FP 必须产生修订 plan；retry 仍失败写审计并排除；其余已验证漏洞报告可生成。

验证命令：

```bash
corepack pnpm build
node scripts/test-report-admission.mjs
node scripts/test-record-explore.mjs
node scripts/verify-http-evidence.mjs
```

### 10.2 验收标准

- 仓库中不存在 `manual_review` 和 `pending_manual_verification` 路径。
- 每个 Exploit `exploited` finding 最终为 Record `verified`、经复审确认 FP 后删除、或复现未通过并审计排除；失败不能等同 FP。
- 每个 `verified` finding 均有完整 HTTP packet；XSS 另有 JS 执行证据。
- retry 成功项使用新鲜变量和新鲜响应，不复用失败尝试的证据。
- retry 仍失败的 finding 均有最终审计与排除记录，保留原始 collector，其余已验证 finding 可生成报告。
- 所有测试与构建通过。

## 11. 实施顺序

1. 固化 verdict 和失败/复审/retry 数据契约。
2. 增加阶段、workflow 接线和 activity 注册。
3. 扩展变量模型与 HTTP replay 执行器。
4. 改造 Record collector 和证据准入规则。
5. 实现失败聚合、vuln-exploit 复审、FP 删除和 record-retry。
6. 接通严格报告准入、最终失败审计和显式排除清单。
7. 更新提示词、文档、agent git paths 和 resume checkpoint。
8. 更新并运行测试，使用最近失败样本做回归验证。

## 12. 当前状态

- [x] 完成代码审查和最近一次运行失败根因分析。
- [x] 明确严格闭环设计与验收标准。
- [x] 实现阶段接驳、activity 注册、持久化 checkpoint 和 resume 路径。
- [x] 实现 `verified | failed` verdict、缺失 verdict 自动失败、结果合并和 verified 不降级。
- [x] 实现结构化变量、TOTP/TTL/response extract、私有变量文件和逐次 replay 刷新。
- [x] 实现 HTTP replay 的 setup/cleanup、空 Header、multipart boundary 和完整 trace 校验。
- [x] 实现失败聚合、离线复审、false-positive 删除、一次有界 retry 和最终失败审计。
- [x] 将 retry 改为仅处理复审批准 finding 的 Record agent，并消费 `variable_requirements`、`record_instructions`、`expected_evidence` 和 `revised_http_replay`。
- [x] retry 使用独立变量目录重新解析变量；XSS 必须重新提交浏览器断言，且截图时间不得早于本轮 retry。
- [x] 实现严格报告准入；缺 verdict、完整 HTTP packet 或 XSS JavaScript 执行证据时拒绝该项，最终审计排除后其余 verified 项继续报告。
- [x] 更新 Record/retry 提示词、HTTP 证据文档和 agent git paths。
- [x] 为最新 retry 重写补充复审字段契约、变量继承和 XSS 新鲜证据的专项回归测试。
- [x] 复跑全部专项测试：`test-report-admission.mjs`、`test-record-explore.mjs` 和 `verify-http-evidence.mjs`（46 个 HTTP 证据场景）均通过。
- [ ] 完成完整 workflow/resume 回归，并用最近一次真实失败样本做端到端验证。
- [x] 完成 monorepo 根级 `corepack pnpm build`。当前环境通过 `/tmp` Corepack shim 向 Turbo 提供 `pnpm` binary 后，CLI 与 Worker 构建均通过。
- [x] 完成 Record/replay 闭环相关改动的最终代码审查；当前工作树保持未提交，等待统一提交安排。

截至 2026-11-02，本地实现、专项回归、类型检查和 monorepo 构建均已通过。尚未执行的验收项只剩完整 workflow/resume 与最近真实失败样本的端到端验证；该项会访问目标系统并运行完整代理流程，应在具备目标授权、模型配置和运行窗口时单独执行。

### 中断后的审计修复

- [x] 修复原始 ID 与报告 ID 重叠时，retry 覆盖另一条漏洞计划和证据的问题。
- [x] 宿主强制每条 finding 每阶段最多三次 HTTP replay；并发重放和成功后重复重放均拒绝，缺失 verdict 保留失败历史。
- [x] 在初始和扩展 exploit collector 中保存真实日志路径，向 Record、复审、retry 传递原始日志及每次失败诊断。
- [x] 最终失败显式写入排除清单并保留审计；重新生成过滤后的报告输入，成功项继续报告。
- [x] 增补隔离回归：ID 重叠、三次上限、并发、成功后不重放、扩展日志、失败排除和 committed 报告组装。

本轮验证：Worker/CLI monorepo 构建、`test-report-admission.mjs`、`test-record-explore.mjs`、`verify-http-evidence.mjs`（46 场景）、三份修复源码的 Biome 检查及 `git diff --check` 均通过。报告组装使用临时 Git 仓库，HTTP 请求仅访问本地测试服务；完整真实目标 workflow/resume 尚未重跑。
