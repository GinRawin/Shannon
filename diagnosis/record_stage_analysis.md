# Record 阶段漏检归因（代码级）— 为什么 7 个“已被证明可利用”的漏洞被剔除

> 结论：**不是这些漏洞不可利用，而是我们的 Record/重放校验链路有多处缺陷。**
> 已定位 4 个代码级缺陷 + 1 个过窄设计 + 1 个失效的 review→retry 闭环。均可在现有代码与工件中复现。
> 修复进展与待讨论项见 `diagnosis/fix_status.md`（A/B 已落地，C/D/E 需拍板）。

## 0. 涉及的 7 个 finding

| run | finding | `record-verification-failures.jsonl` 的 `last_failure.error` |
|---|---|---|
| ai-media | AUTH-02 | `Extracted variables must have uppercase names distinct from operator variables` |
| ai-media | AUTHZ-13 | `HTTP impact assertion failed (status 200)` |
| ai-media | AUTHZ-26 | `HTTP impact assertion failed (status 200)`（首轮因 `Replay plan contains literal authentication material` 被拒） |
| cp-dev | AUTH-01 | `Extracted variables must have uppercase names distinct from operator variables` |
| cp-dev | AUTH-02 | `Extracted variables must have uppercase names distinct from operator variables` |
| cp-dev | XSS-01 | `Host browser replay failed … No trusted JavaScript execution receipt was produced.` |
| imwl | XSS-03 | 同上 |

共同点：`review_verdict=retry` 且 `review_reason` 明确 “not a false positive”；`record_report_exclusions.json` 的理由是
`missing verified Record verdict` / `missing complete associated HTTP packet` / `missing JavaScript execution evidence`。

---

## 根因 A（3 项，我们的缺陷）— TS 计划校验 与 Python 运行器校验不对称

**代码**
- 计划 schema：`apps/worker/src/services/http-replay.ts:57-63`
  ```ts
  save_json: Type.Optional(
    Type.Record(Type.String(), Type.String({ minLength: 1, … })),  // 键只要求 String，无大写约束
  ),
  save_headers: Type.Optional(Type.Record(Type.String(), Type.String({ minLength: 1 }))),
  ```
- 计划预检：`replayPlanError()`（同文件 :103-）只校验 URL 前缀 / redirect / 未解析占位符 / body 格式，**不校验 save 变量名**。
- 运行器（Python，内嵌于同文件）在**运行时**才强制：`http-replay.ts:303` 与 `:312`
  ```python
  if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or name in VARIABLES:
      raise ValueError("Extracted variables must have uppercase names distinct from operator variables")
  ```
  （`VARIABLES = ("BASE_URL","BEARER_TOKEN","COOKIE","USERNAME","PASSWORD","OTP")`）

**后果**：计划在 TS 侧“校验通过”，到 Python 才炸，错误信息含糊；作者/重试 agent 无早期反馈。
**命中**（且是**重试修订计划**引入/保留的）：
- ai-media AUTH-02：revised `save_json: { created_media_id: "data.mediaId" }`（小写）
- cp-dev AUTH-01：revised `save_json: { obj }` + `save_headers: { acao }`（小写）
- cp-dev AUTH-02：revised `save_json: { tok }`（小写）

证据：`deliverables/record-verification-failures.jsonl` 中各条的 `revised_replay_plan`。

**修法**：给 `save_json`/`save_headers` 的键加 pattern `^[A-Z][A-Z0-9_]*$` 并禁止等于 `REPLAY_VARIABLES`；或在生成/重试阶段自动大写化；错误信息给出具体键名。

---

## 根因 B（1 项，我们的缺陷）— 64 位雪花 ID 被 JS 当 Number 丢精度

ai-media `AUTHZ-13`：计划里同一个 `copyWritingId` 出现两种形态——
- setup：字符串 `"1774725156766629890"`（保留）；
- impact 步 `body_json.copyWritingId`：数字 `1774725156766630000`（**被四舍五入**，`…6629890 → …6630000`）。

服务器据此返回 `{"code":"80004","msg":"任务不存在"}`，断言 `{"data":9}` 失败。
证据：`record-verification-failures.jsonl` 该条 `original/revised` 的 body ids = `[1774725156766630000,"1774725156766629890"]`。

**根因**：计划经 JS `JSON.parse/JSON.stringify`，`> 2^53` 的整数被 Number 截断（这是标准 JSON/JS 行为，不是目标的问题）。
**修法**：管道层对 `body_json` 中的大整数强制字符串化（或在序列化时保护），生成指南明确“大 ID 用字符串”。
**次要**：断言用绝对计数 `"data":9` 本身脆弱（review 也指出），应改“新增标记”相对断言。

---

## 根因 C（1 项，我们的缺陷：过宽）— “literal authentication material” 误杀合法断言

**代码**
- `record-collector.ts:219` / `:222` 调用 `hasLiteralReplayAuthentication(plan)` 与 `containsReplaySecret(plan, options.secrets)`。
- `hasLiteralReplayAuthentication()`（`http-replay.ts:151`）**只扫 headers**，不是本次触发点。
- 真正的触发点是 `containsReplaySecret()`（`http-replay.ts:161`）：把传入的 `secrets` 逐个与计划里的 **字符串值**（含 `expect.body_contains`）做子串匹配。
- `secrets` 来自 `activities.ts:1627`：
  ```ts
  secrets: [ ...captureRedactions.map(v=>v.value),
             ...Object.values(resolution.values).filter(v => v !== origin) ]   // ← 所有“已解析重放变量值”
  ```

ai-media `AUTHZ-26`：断言 `expect.body_contains = "\"createdUser\":\"cqpv8a\""`；而 `cqpv8a` 是**操作者自己的账号 `account_no`**，被作为重放变量值保存（`scratchpad/auth-state.json`）。于是这条**合法的影响证据**被判为“literal authentication material”直接拒绝。

**修法**：区分“凭据”（cookie/Authorization/token/password → 必须拒绝并强制 `${VAR}`）与“身份标识”（账号名/id → 允许出现在断言里；导出 `reproduce.sh` 时再脱敏替换），或自动把匹配值替换为变量引用而不是整条判死。

---

## 根因 D（2 项，按设计但过窄）— 客户端 XSS 的 receipt 模型只认“精确 dialog”

**代码**
- `record-collector.ts:213`：XSS 也**必须先有结构化 HTTP 计划**，否则 `No structured HTTP verification plan was saved`。
- `hasTrustedBrowserReplay()`（`browser-replay.ts:370`，:393）要求 `assertion_type='dialog_exact'`、`proof.observed === proof.expected`、`expected` 匹配 `^shannon_xss_[a-f0-9]{48}$`，且 `http_capture_ids` 与 HTTP 抓包集合**完全一致**。
- 采集（`browser-replay.ts:266`）只接受 `page.on('dialog')` 且 `dialog.message() === marker`。

**后果**
- imwl `XSS-03`：sink 在 `refer`（URL hash，**从不发送到服务器**）→ 无有意义的 HTTP 断言；实际失败于 `browser_steps`（`javascript:` 目标/登录流程未弹出 dialog）→ 无 receipt。
- cp-dev `XSS-01`：失败于 `browser_steps`/`execution_signal`（未匹配到 marker 的 dialog）→ 无 receipt。

只写 DOM（不 alert）的 XSS、或被浏览器拦截的 `javascript:` 导航，**永远无法**产出该 receipt。
**修法**：为纯客户端 sink 增加“DOM 副作用/执行”类 receipt（注入唯一标记并断言 DOM 状态），并允许 browser-only 验证（无 HTTP 断言时以 DOM 证据替代 `complete_http_packet`）。

---

## 根因 E（放大所有上述问题，我们的缺陷）— review→retry 闭环无效

**代码**
- 重试直接使用 review 产出的修订计划：`activities.ts:2469`
  ```ts
  const plans = new Map(reviews.flatMap(r => r.revised_http_replay ? [[r.finding_id, r.revised_http_replay]] : []));
  ```
- 但 `exploit-review-collector.ts` 对 `revised_http_replay` 只做与主流程**相同的、不严的** schema 校验（不含大写变量规则、不含大整数规则、不交叉校验 verb）。
- 重试只跑 1 次，失败即判死（进入 `record_report_exclusions.json`）。

**观察到的三种失效**：
1. **修订计划引入新违规**：AUTH-01/02 的小写 save 键（根因 A 就是被“修订”出来的）。
2. **修订计划不落地/次序错**：imwl XSS-03，review 文本里已给出 `GET /app/` 的 HTTP 计划，但 collector 条目/重放过程中先报 `no_http_replay_plan`，最终仍死在 `browser_steps`。
3. **修订未真正修复**：AUTHZ-13 修订仍用被截断的 id；AUTHZ-26 修订去掉 literal 后仍断言失败。

**修法**：review 生成的修订计划必须过与 runner **同一套**约束（大写变量名、大整数、verb 与 inventory 一致、非 literal 凭据）后才能交付 retry；retry 失败应回到“计划修复”而非直接判死。

---

## 汇总表：7 项 → 根因

| finding | 直接错误 | 主根因 | 是否我们的问题 |
|---|---|---|---|
| ai-media AUTH-02 | 大写变量名 | A（+retry 引入）| ✅ |
| cp-dev AUTH-01 | 大写变量名 | A（+retry 引入）| ✅ |
| cp-dev AUTH-02 | 大写变量名 | A（+retry 引入）| ✅ |
| ai-media AUTHZ-13 | 断言失败 | B（精度）| ✅（+断言设计）|
| ai-media AUTHZ-26 | literal 拒绝 / 断言失败 | C（过宽）| ✅ |
| cp-dev XSS-01 | 无 JS receipt | D（过窄）| ⚠️ 部分 |
| imwl XSS-03 | 无 JS receipt | D（过窄）| ⚠️ 部分 |
| （全部）| 一次重试即判死 | E（闭环无效）| ✅ |

---

## 可证伪的最小验证（建议先做）

1. **复现 A**：构造含 `save_json:{tok}` 的计划，调用 `replayPlanError()` 应返回错误——当前返回 `undefined`（通过）；再跑 Python runner 应报大写错误。→ 证明 schema/runner 不一致。
2. **复现 B**：`JSON.parse(JSON.stringify({id:1774725156766629890}))` → `{id:1774725156766630000}`。→ 证明大整数被截断。
3. **复现 C**：令 `resolution.values` 含 `cqpv8a`，构造 `expect.body_contains` 含 `"createdUser":"cqpv8a"`，断言 `containsReplaySecret(plan, secrets) === true`。→ 证明合法断言被误杀。
4. **复现 D**：构造“仅 DOM 写入、不弹 dialog”的 XSS PoC，断言 `hasTrustedBrowserReplay()` 恒为 false。→ 证明 receipt 模型过窄。
5. **回归**：修 A/B/C/E 后重跑这 7 项的 Record，应全部转为通过（AUTHZ-13 需同时改用非绝对计数断言）。
