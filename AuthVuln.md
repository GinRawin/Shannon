# AuthVuln.md

## 结论先行

这次 Photoview 2.4 扫描里最终报告的 `AUTH-01` 是：

> `authorizeUser` 登录 mutation 缺少 per-IP / per-account 速率限制、锁定、退避、CAPTCHA 和失败登录监控，导致可以无限制撞库/爆破；exploit 阶段用 200 次错误登录证明没有 throttling，又用 10 个常见密码字典在第 6 次拿到管理员 token。

需要注意一个编号变化：认证分析阶段把这个问题放进队列时是 `AUTH-04`；报告阶段根据严重性和展示顺序重编号为最终报告里的 `AUTH-01`。对应关系在：

- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/auth_renumber_map.json:4`
- `workspaces/host-docker-internal_shannon-1790063197135/Security-Assessment-Report.md:217`

还需要先纠正一个容易混淆的点：`vuln-injection` 是并行运行的注入漏洞分析分支，它没有发现这个认证漏洞。真正把登录无限制爆破放入 exploit 队列的是 `vuln-auth` 认证分析分支。注入分支发现的是 SQLi / identifier injection 相关问题。

## 本次运行与模型线索

本次运行目录是：

```text
workspaces/host-docker-internal_shannon-1790063197135/
```

最终 Markdown 报告记录的模型字段是：

```text
Security-Assessment-Report.md:11
Model: ep-20260921205410-m6s4d
```

本地 `models.volcengine.json:8` 也有同一个 endpoint id。仓库里另有 benchmark 文件 `benchmark/photoview-deepseek-v4-flash.sarif:1375` 记录 `deepseek/deepseek-v4-flash-0731`，但这属于 benchmark 产物，不是这个运行目录里最终报告直接写出的模型名。因此本文档把“本次运行”按 `host-docker-internal_shannon-1790063197135` 的日志和 deliverables 还原。

## Shannon 怎样装载这些提示词

Shannon 的 agent 并不是把完整 rendered prompt 持久化为一个单独文件；它在运行时由模板、include 和变量插值得到系统提示词。相关代码：

- `apps/worker/src/session-manager.ts:26`：`pre-recon` 使用 `pre-recon-code`
- `apps/worker/src/session-manager.ts:54`：`vuln-auth` 使用 `vuln-auth`
- `apps/worker/src/session-manager.ts:89`：`exploit-auth` 使用 `exploit-auth`
- `apps/worker/src/services/agent-execution.ts:203`：执行前调用 `loadPrompt`
- `apps/worker/src/services/prompt-manager.ts:505`：读取模板
- `apps/worker/src/services/prompt-manager.ts:544`：展开 `@include`
- `apps/worker/src/services/prompt-manager.ts:547`：插入变量
- `apps/worker/src/services/prompt-manager.ts:361` 到 `:362`：插入 `{{WEB_URL}}`、`{{REPO_PATH}}`

因此下面说“提示词是什么”时，分两层：

1. 源模板：`apps/worker/prompts/*.txt`
2. 本次运行提供给 agent 的上下文：目标 URL、repo 路径、上一阶段 deliverable、auth state、login instructions、漏洞类别等

## 阶段 1：pre-recon

### 使用的提示词模板

模板文件：

```text
apps/worker/prompts/pre-recon-code.txt
```

这个模板把 agent 定义成“安全导向的代码审查 Principal Engineer”。关键指令包括：

```text
Role: You are a Principal Engineer specializing in rapid, security-focused code review.
Objective: ... analyze the provided source code to generate a security-relevant architectural summary ...
Code is Ground Truth: ... rooted in actual source code ...
Phase Sequence: PRE-RECON (You) -> RECON -> VULN ANALYSIS (5 agents) -> EXPLOITATION (5 agents) -> REPORTING
Your Input: Target application source code in the working directory
Your Output: .shannon/deliverables/pre_recon_deliverable.md
Document defensive mechanisms (WAF, rate limiting, input validation) for exploitation planning
```

对应行号：

- `apps/worker/prompts/pre-recon-code.txt:1`
- `apps/worker/prompts/pre-recon-code.txt:3`
- `apps/worker/prompts/pre-recon-code.txt:9`
- `apps/worker/prompts/pre-recon-code.txt:43`
- `apps/worker/prompts/pre-recon-code.txt:45`
- `apps/worker/prompts/pre-recon-code.txt:46`
- `apps/worker/prompts/pre-recon-code.txt:70`

它还要求 pre-recon 启动 6 个子任务：

- Architecture Scanner
- Entry Point Mapper
- Security Pattern Hunter
- XSS/Injection Sink Hunter
- SSRF/External Request Tracer
- Data Security Auditor

其中和本认证漏洞最相关的是 Security Pattern Hunter。模板原话要求它：

```text
Identify authentication flows, authorization mechanisms, session management, and security middleware.
```

来源：`apps/worker/prompts/pre-recon-code.txt:114`

### 本次运行给 pre-recon 的信息

本次运行开始于：

```text
workspaces/.../.shannon/agents/pre-recon.log:2
[2026-09-22 07:47:41] [AGENT] pre-recon: Starting
```

pre-recon 拿到的核心上下文是：

- 目标代码目录：运行容器内 `/repos/repo`
- deliverable 输出目录：`/repos/repo/.shannon/deliverables/`
- scratchpad：`/repos/repo/.shannon/scratchpad/`
- 漏洞类别：后续要覆盖 authentication、authorization、injection、XSS、SSRF、misc 等分支
- scope：只分析可由网络请求触发的攻击面

日志显示它在 07:48:38 启动了三个第一阶段子 agent：

- Architecture Scanner：`pre-recon.log:8`
- Entry Point Mapper：`pre-recon.log:9`
- Security Pattern Hunter：`pre-recon.log:10`

Security Pattern Hunter 的 prompt 明确要求寻找：

- 所有 auth endpoints
- login / logout / initial setup / token refresh / password reset
- token 创建和校验
- session 存储位置与 cookie flag
- authorization model
- password hashing / password policy
- CORS、CSRF、安全 header、rate limiting、request size limit
- SSO/OAuth/OIDC
- admin role
- share token security

对应完整子任务 prompt 见：

```text
workspaces/.../.shannon/agents/pre-recon.log:10
```

### pre-recon 已经发现了什么

pre-recon 的产物是：

```text
workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/pre_recon_deliverable.md
```

与 AUTH-01 直接相关的信息有：

```text
pre_recon_deliverable.md:23
Authentication uses opaque database-backed access tokens ... delivered in an auth-token cookie ...
```

以及：

```text
pre_recon_deliverable.md:25
No rate limiting exists on authorizeUser or share-password validation ...
```

pre-recon 还列出了关键代码位置：

```text
pre_recon_deliverable.md:37
authorizeUser(username,password) ... resolver api/graphql/resolvers/user.go:75-104
credential verification api/graphql/models/user.go:76-99
```

这一步对后续的价值是：它把 `authorizeUser` 识别为公开登录入口，并把“缺少 rate limiting”作为安全情报写进了基础报告。但 pre-recon 不负责 exploit，也不会生成 PoC。

## 阶段 2：recon

### 使用的提示词模板

模板文件：

```text
apps/worker/prompts/recon.txt
```

这个模板把 agent 定义为 Reconnaissance Analyst / Attack Surface Mapper。关键指令：

```text
Your goal is to create a comprehensive, structured map of the application's attack surface.
You are NOT looking for vulnerabilities yet.
Your analysis must begin by reading ... pre_recon_deliverable.md.
URL: {{WEB_URL}}
Filesystem: {{REPO_PATH}}/
Phase Sequence: PRE-RECON (Complete) -> RECONNAISSANCE (You) -> VULN ANALYSIS ...
Your Input: .shannon/deliverables/pre_recon_deliverable.md
Your Output: .shannon/deliverables/recon_deliverable.md
Document authentication mechanisms and session management for Auth specialist
```

对应行号：

- `apps/worker/prompts/recon.txt:6`
- `apps/worker/prompts/recon.txt:10`
- `apps/worker/prompts/recon.txt:14`
- `apps/worker/prompts/recon.txt:17`
- `apps/worker/prompts/recon.txt:86`
- `apps/worker/prompts/recon.txt:88`
- `apps/worker/prompts/recon.txt:89`
- `apps/worker/prompts/recon.txt:109`

### 本次运行给 recon 的信息

recon 开始于：

```text
workspaces/.../.shannon/agents/recon.log:2
[2026-09-22 08:59:15] [AGENT] recon: Starting
```

它的起始输入是：

- `pre_recon_deliverable.md`
- 目标：`http://host.docker.internal:4800`
- Playwright session：日志中使用 `agent2`
- 已保存的 auth state：`.shannon/auth-state.json`
- 源码路径：容器内 `/repos/repo`

日志显示它先加载 pre-recon，再加载浏览器状态：

- `recon.log:7`：读取 pre-recon
- `recon.log:10`：读取 `playwright-cli` skill
- `recon.log:11` 到 `:16`：加载 auth-state、打开目标、检查 cookie 和 URL

随后它在 `recon.log:30` 到 `:35` 启动多个并行子任务：

- Route/Endpoint Mapper
- Authorization Checker
- Input Validator / Input Vector Analyst
- Session/Authentication Handler Analyst
- Authorization Architecture Analyst
- Injection Source Tracer

和 AUTH-01 最相关的是 Session/Authentication Handler Analyst。它的子任务 prompt 要求完整追踪：

- login flow
- bcrypt verification
- token generation
- token 到客户端的方式
- cookie name 和 flags
- session validation flow
- share-token flow
- logout / revocation
- password change 是否 invalidates tokens
- WebSocket auth
- no rate limiting / no lockout 等 authentication weaknesses

来源：`workspaces/.../.shannon/agents/recon.log:33`

### recon 产物提供了哪些信息

产物：

```text
workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/recon_deliverable.md
```

recon 明确写出了登录流：

```text
recon_deliverable.md:28
Entry Points: /login (GraphQL mutation authorizeUser) ...

recon_deliverable.md:29
Client POSTs GraphQL mutation authorizeUser(username,password).
Server verifies password with bcrypt.CompareHashAndPassword ...
GenerateAccessToken creates a 24-byte crypto/rand value ...
token is returned in the GraphQL response body ...
client JavaScript writes document.cookie ...
```

它在 API inventory 中把 `authorizeUser` 作为公开匿名入口列出：

```text
recon_deliverable.md:57
POST /api/graphql ...

recon_deliverable.md:58
POST /api/graphql [mutation authorizeUser] | anon | ... No rate limiting, no lockout.
```

它还在 input vectors 中列出用户名和密码参数：

```text
recon_deliverable.md:115
username @ api/graphql/resolvers/user.go:75 ... no length policy, no rate limit

recon_deliverable.md:116
password @ api/graphql/resolvers/user.go:75 ... bcrypt cost 12, no length policy
```

这一步的作用是把 pre-recon 的代码级线索变成面向后续 specialist 的攻击面地图：`POST /api/graphql [mutation authorizeUser]`、匿名可达、无 rate limit / lockout、代码位置明确。

## 阶段 3：vuln-injection 分支

### 使用的提示词模板

模板文件：

```text
apps/worker/prompts/vuln-injection.txt
```

这个模板定义的是 Injection Analysis Specialist。关键指令：

```text
You are an Injection Analysis Specialist ... for SQLi, Command Injection, LFI/RFI, SSTI, Path Traversal, and Deserialization vulnerabilities.
Your mission is to identify where untrusted input reaches dangerous sinks ...
Phase Sequence: RECON (Complete) -> INJECTION ANALYSIS (You) -> EXPLOITATION
Your Input: .shannon/deliverables/recon_deliverable.md
Your Output: .shannon/deliverables/injection_analysis_deliverable.md
```

对应行号：

- `apps/worker/prompts/vuln-injection.txt:2`
- `apps/worker/prompts/vuln-injection.txt:7`
- `apps/worker/prompts/vuln-injection.txt:49`
- `apps/worker/prompts/vuln-injection.txt:51`
- `apps/worker/prompts/vuln-injection.txt:52`

它的方法论集中在：

- source -> sink trace
- SQL slot type
- sanitizer 是否匹配 sink context
- witness payload
- 只把 externally exploitable 的 injection finding 加入 injection exploit queue

来源：`apps/worker/prompts/vuln-injection.txt:127` 到 `:177`

### 本次运行给 injection agent 的信息

injection 分支和 auth 分支是在 recon 之后并行运行的。它的输入主要是：

- `recon_deliverable.md`
- pre-recon 中列出的 injection sources
- 目标 URL 和 repo 路径
- login instructions / shared session

它的产物是：

```text
workspaces/.../.shannon/deliverables/injection_analysis_deliverable.md
```

产物结论：

```text
injection_analysis_deliverable.md:5
One high-confidence, unauthenticated SQL injection was confirmed in the album-download REST route ...
```

这个 finding 是 album download route 的 SQLi，不是登录认证漏洞。注入分支确实会看到 `authorizeUser` 的 username 是参数化查询并把它列为安全：

```text
injection_analysis_deliverable.md:45
username ... Parameterized query (`WHERE username = ?`) with bound argument. | SAFE
```

所以，对 AUTH-01 的发现链来说，vuln-injection 是旁支背景：它没有把 `authorizeUser` 的 rate limiting 问题推给 auth exploit；它只处理“输入是否进入 SQL/命令/文件/template/deserialization sink”。

## 阶段 4：vuln-auth 认证分析分支

### 使用的提示词模板

模板文件：

```text
apps/worker/prompts/vuln-auth.txt
```

这个模板把 agent 定义为 Authentication Analysis Specialist。关键指令：

```text
Your mission is to identify and document every logical flaw in the application's authentication model.
Success criterion: ... source-to-sink trace ... missing defense ... testable hypothesis for the Exploitation phase.
Your primary source of truth ... recon_deliverable.md.
Phase Sequence: RECON (Complete) -> AUTH ANALYSIS (You) -> EXPLOITATION
Your Input: recon_deliverable.md, pre_recon_deliverable.md
Your Output: auth_analysis_deliverable.md
```

对应行号：

- `apps/worker/prompts/vuln-auth.txt:6`
- `apps/worker/prompts/vuln-auth.txt:8`
- `apps/worker/prompts/vuln-auth.txt:40`
- `apps/worker/prompts/vuln-auth.txt:46`
- `apps/worker/prompts/vuln-auth.txt:48`
- `apps/worker/prompts/vuln-auth.txt:49`

该模板的 exploitation queue 格式要求每个漏洞包含：

- ID
- vulnerability_type
- externally_exploitable
- source_endpoint
- vulnerable_code_location
- missing_defense
- exploitation_hypothesis
- suggested_exploit_technique
- confidence
- code_locations
- notes

来源：`apps/worker/prompts/vuln-auth.txt:91` 到 `:109`

最关键的是方法论第 2 节：

```text
Rate limiting / CAPTCHA / monitoring
- For login, signup, reset/recovery, and token endpoints, verify per-IP and/or per-account rate limits exist.
- For repeated failures, verify lockout/backoff or CAPTCHA is triggered.
- Verify basic monitoring/alerting exists for failed-login spikes and suspicious activity.
If failed -> classify: abuse_defenses_missing -> suggested attack: brute_force_login / credential_stuffing / password_spraying.
```

来源：`apps/worker/prompts/vuln-auth.txt:127` 到 `:131`

这几行就是 AUTH-01 被发现的规则源头。

### 本次运行给 auth-vuln 的信息

auth-vuln 开始于：

```text
workspaces/.../.shannon/agents/auth-vuln.log:2
[2026-09-22 09:43:52] [AGENT] auth-vuln: Starting
```

它读取：

- `recon_deliverable.md`：`auth-vuln.log:9`
- `pre_recon_deliverable.md`：`auth-vuln.log:10`

它建立 todo 时，明确把 rate limiting 放成一个任务：

```text
auth-vuln.log:11
Analyze rate limiting/lockout/monitoring on login and share-password
```

然后启动了四个子任务：

- session management code
- token properties
- login flow and password policy
- transport and headers

其中 `login flow and password policy` 的 prompt 明确要求回答：

```text
Is there any rate limiting, account lockout, backoff, or CAPTCHA on authorizeUser?
Search the repo for rate limit / throttle / lockout / attempt counters.
Check api/utils for throttle helpers.
Is there any rate limiting on shareTokenValidatePassword?
```

来源：`workspaces/.../.shannon/agents/auth-vuln.log:15`

日志随后显示该子任务确实执行了搜索：

```text
auth-vuln.log:46
grep: rate|throttle|lockout|attempt|backoff|captcha

auth-vuln.log:64
read: /repos/repo/api/utils/Throttle.go
```

也就是说，auth-vuln 的发现过程是：

1. 从 recon 得到公开登录入口 `POST /api/graphql [mutation authorizeUser]`
2. 从 pre-recon / recon 得到代码位置 `api/graphql/resolvers/user.go:75` 和 `api/graphql/models/user.go:76`
3. 根据 auth prompt 的方法论要求检查 rate limit / lockout / CAPTCHA / monitoring
4. 搜索代码中的 throttle / rate limit / attempt counter
5. 发现 `api/utils/Throttle.go` 存在，但只服务 scanner queue，不作用于登录
6. 用少量 live probe 确认 25 次快速失败登录都没有 429/lockout
7. 生成 exploitation queue 条目

### auth-vuln 产物提供了哪些信息

认证分析 deliverable：

```text
workspaces/.../.shannon/deliverables/auth_analysis_deliverable.md
```

它在 executive summary 中总结：

```text
auth_analysis_deliverable.md:5
... no login or share-token rate limiting ...
```

它把这类问题归入主导模式：

```text
auth_analysis_deliverable.md:19
Pattern 3: No Abuse Defenses on Authentication

auth_analysis_deliverable.md:20
authorizeUser, share-token lookup, and share-password validation have no rate limiting, lockout, backoff, CAPTCHA, or monitoring ...

auth_analysis_deliverable.md:22
Representative Findings: AUTH-VULN-04 ...
```

它在 blind spots 里写出了分析阶段的 live probe 边界：

```text
auth_analysis_deliverable.md:59
Rate-Limit Long-Run Behavior

auth_analysis_deliverable.md:60
Absence of rate limiting was confirmed with 25 rapid failed logins (all HTTP 200, no 429) ...
```

结构化 exploitation queue 中该条目是：

```text
auth_exploitation_queue.json:124
{
  "vulnerability_type": "Abuse_Defenses_Missing",
  "source_endpoint": "POST /api/graphql [mutation authorizeUser]",
  "vulnerable_code_location": "api/graphql/resolvers/user.go:75",
  "missing_defense": "No per-IP/per-account rate limiting, lockout, backoff, CAPTCHA, or failed-login monitoring on authorizeUser.",
  "exploitation_hypothesis": "An attacker can brute-force or credential-stuff accounts without limit, eventually authenticating as a valid user (including an admin).",
  "suggested_exploit_technique": "brute_force_login",
  "confidence": "high",
  "ID": "AUTH-04"
}
```

对应行号：

- `auth_exploitation_queue.json:125`
- `auth_exploitation_queue.json:148`
- `auth_exploitation_queue.json:149`
- `auth_exploitation_queue.json:150`
- `auth_exploitation_queue.json:151`
- `auth_exploitation_queue.json:152`
- `auth_exploitation_queue.json:153`
- `auth_exploitation_queue.json:155`

auth-vuln 原始 submit 时使用的是 `AUTH-VULN-04`，后续被系统标准化为 `AUTH-04`，最终报告重编号为 `AUTH-01`。原始 submit 见：

```text
workspaces/.../.shannon/agents/auth-vuln.log:337
```

## 阶段 5：auth exploit agent 如何生成 PoC

### 使用的提示词模板

模板文件：

```text
apps/worker/prompts/exploit-auth.txt
```

这个模板把 agent 定义成主动验证 broken authentication 的 Authentication Exploitation Specialist。关键指令：

```text
Your mission is to systematically and exhaustively weaponize every single potential authentication vulnerability ...
All exploitation must be performed against the specified target: {{WEB_URL}}
An exploit is executing an unauthorized or unintended action against the target application.
"No rate limiting" -> Attempt brute force/enumeration attacks with many requests
Your actionable exploitation queue is located at .shannon/deliverables/auth_exploitation_queue.json.
Before beginning exploitation, read pre_recon_deliverable.md, recon_deliverable.md, auth_analysis_deliverable.md.
task agent: Mandatory coder-executor for brute force batches, credential stuffing, token replay automation, and any scripted workflow.
Use the task agent to execute all bulk or repetitive auth attacks.
```

对应行号：

- `apps/worker/prompts/exploit-auth.txt:6`
- `apps/worker/prompts/exploit-auth.txt:17`
- `apps/worker/prompts/exploit-auth.txt:21`
- `apps/worker/prompts/exploit-auth.txt:89`
- `apps/worker/prompts/exploit-auth.txt:113`
- `apps/worker/prompts/exploit-auth.txt:116`
- `apps/worker/prompts/exploit-auth.txt:151`
- `apps/worker/prompts/exploit-auth.txt:161`

模板还要求它先执行主动攻击，再做影响证明：

```text
Stage 1: Active Attack Execution
Stage 2: Impact Demonstration (Impersonation)
```

来源：`apps/worker/prompts/exploit-auth.txt:205` 到 `:213`

### 本次运行给 auth-exploit 的信息

auth-exploit 开始于：

```text
workspaces/.../.shannon/agents/auth-exploit.log:2
[2026-09-22 12:35:45] [AGENT] auth-exploit: Starting
```

它先读取了：

- `auth_exploitation_queue.json`：`auth-exploit.log:3`
- `pre_recon_deliverable.md`：`auth-exploit.log:4`
- `auth_analysis_deliverable.md`：`auth-exploit.log:5`
- `recon_deliverable.md`：`auth-exploit.log:9`

然后建立 todo，队列里仍然使用分析阶段编号：

```text
auth-exploit.log:13
AUTH-04: No login rate limiting - brute force
```

这对应最终报告里的 `AUTH-01`。

### 生成 brute_login.py 的具体 prompt

当 exploit agent 处理 `AUTH-04` 时，它没有手写 bash 爆破，而是根据 `exploit-auth.txt` 的要求把脚本任务委托给 task agent。日志完整记录了这条子任务 prompt：

```text
workspaces/.../.shannon/agents/auth-exploit.log:40
```

核心内容是：

```text
Role: security testing script writer.
Write and run a Python script (save to /repos/repo/.shannon/scratchpad/brute_login.py)
to test login rate limiting/brute-force on a GraphQL API.

Inputs:
1. Target endpoint: http://host.docker.internal:4800/api/graphql (POST, JSON)
2. Mutation: mutation { authorizeUser(username: "USER", password: "PW") { success status token } }
3. Test A: send 200 login attempts with a wrong password for username "victim_a3";
   record every HTTP status code and whether any response is HTTP 429 or contains
   "locked"/"too many"/"rate".
4. Test B: dictionary attack username "123" against a 10-password wordlist.
   Print the password that returns success=true and the token prefix, plus the attempt index.
5. Print a concise summary: total attempts, count by HTTP status, any throttling observed,
   and the recovered credential (if any).
Success Criteria: ... show whether 200 rapid failures were throttled, and which wordlist entry succeeded.
```

这里的 `username "123"` 和 wordlist 是测试环境中的 PoC 数据。报告阶段把管理员用户名和密码用 `$username` / `$password` 占位，避免直接扩散完整凭据。

### brute_login.py 做了什么

脚本保存于：

```text
workspaces/host-docker-internal_shannon-1790063197135/.shannon/scratchpad/brute_login.py
```

脚本结构：

1. `ENDPOINT = "http://host.docker.internal:4800/api/graphql"`  
   来源：`brute_login.py:13`

2. `gql(username, password)` 用 stdlib `urllib.request` POST JSON 到 GraphQL endpoint  
   来源：`brute_login.py:17` 到 `:39`

3. GraphQL mutation 是：

   ```text
   mutation { authorizeUser(username: ..., password: ...) { success status token } }
   ```

   来源：`brute_login.py:19` 到 `:22`

4. `is_throttled` 判断 HTTP 429，或者响应正文包含 `locked` / `too many` / `rate`  
   来源：`brute_login.py:42` 到 `:48`

5. Test A 循环 200 次错误密码：

   ```text
   username = victim_a3
   password = wrong-password-<i>
   ```

   来源：`brute_login.py:67` 到 `:90`

6. Test B 对管理员账号跑 10 个常见密码：

   ```text
   ["password", "123456", "admin", "letmein", "qwerty",
    "123", "1234", "111111", "abc123", "password1"]
   ```

   来源：`brute_login.py:93` 到 `:110`

7. summary 输出：

   - 总 attempts
   - Test A HTTP status counts
   - Test B HTTP status counts
   - 是否 throttled
   - 成功密码的 index
   - token prefix，而不是完整 token

   来源：`brute_login.py:113` 到 `:140`

脚本被写入和执行的日志：

```text
auth-exploit.log:57
write: /repos/repo/.shannon/scratchpad/brute_login.py

auth-exploit.log:59
python3 brute_login.py ... tee /tmp/brute_out.txt

auth-exploit.log:64
completed
```

### PoC 结果如何进入最终报告

认证 exploit deliverable 中 `AUTH-01` 写出了结果：

```text
auth_exploitation_evidence.md:5
AUTH-01: No login rate limiting or lockout allows unlimited password guessing and admin account takeover

auth_exploitation_evidence.md:9
200 rapid failed logins (all HTTP 200, none throttled) ...

auth_exploitation_evidence.md:10
10-entry common-password dictionary recovered the administrator's password at attempt 6 ...
```

证明片段：

```text
auth_exploitation_evidence.md:47
Total attempts: 210 (Test A=200, Test B=10)

auth_exploitation_evidence.md:48
HTTP status breakdown: {200: 200}

auth_exploitation_evidence.md:49
Throttling observed: NO

auth_exploitation_evidence.md:55
credential recovered ... at attempt 6

auth_exploitation_evidence.md:64
myUser ... admin:true
```

最终报告的同一 finding：

```text
Security-Assessment-Report.md:217
AUTH-01: No Rate Limiting or Account Lockout on Login Endpoint

Security-Assessment-Report.md:228
200 rapid failed logins ... all HTTP 200 ... short common-password dictionary ...

Security-Assessment-Report.md:231
... recovered the administrator's password at attempt 6 ...
```

报告中 exploit 步骤被整理成三个步骤：

1. 发送 200 次错误登录确认没有 throttling
2. 对管理员账号跑短字典
3. 用 recovered token 调 `myUser { id username admin }` 确认管理员身份

来源：`Security-Assessment-Report.md:233` 到 `:293`

## 数据流总结

这个认证漏洞的发现链路可以压缩成下面这条：

```text
pre-recon
  -> 识别 authorizeUser 登录入口、opaque token、无 rate limiting 线索
  -> 写入 pre_recon_deliverable.md

recon
  -> 通过 live + source 映射攻击面
  -> 确认 POST /api/graphql [mutation authorizeUser] 是匿名可达登录入口
  -> 标注 No rate limiting, no lockout
  -> 写入 recon_deliverable.md

vuln-auth
  -> 根据 auth 方法论第 2 节检查 rate limiting / CAPTCHA / monitoring
  -> 搜索 throttle / lockout / attempts
  -> 发现 authorizeUser 没有 per-IP/per-account rate limit、lockout、backoff、CAPTCHA、monitoring
  -> 25 次快速失败登录均 HTTP 200
  -> 写入 auth_analysis_deliverable.md
  -> 入队 AUTH-04，technique = brute_force_login

auth-exploit
  -> 读取 auth_exploitation_queue.json、pre-recon、recon、auth analysis
  -> 处理 AUTH-04
  -> task agent 生成 brute_login.py
  -> Test A: 200 次错误登录，0 次 throttling
  -> Test B: 10 个常见密码，第 6 次拿到管理员 token
  -> 用 token 查询 myUser，确认 admin:true
  -> 写入 auth_exploitation_evidence.md

report
  -> 根据 auth_renumber_map.json 把 AUTH-04 重编号为 AUTH-01
  -> 写入 Security-Assessment-Report.md
```

## 关键源文件索引

### Prompt 模板

- `apps/worker/prompts/pre-recon-code.txt`
- `apps/worker/prompts/recon.txt`
- `apps/worker/prompts/vuln-injection.txt`
- `apps/worker/prompts/vuln-auth.txt`
- `apps/worker/prompts/exploit-auth.txt`

### 本次运行日志

- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/pre-recon.log`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/recon.log`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/injection-vuln.log`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/auth-vuln.log`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/agents/auth-exploit.log`

### 本次运行产物

- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/pre_recon_deliverable.md`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/recon_deliverable.md`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/injection_analysis_deliverable.md`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/auth_analysis_deliverable.md`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/auth_exploitation_queue.json`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/auth_exploitation_evidence.md`
- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/deliverables/auth_renumber_map.json`
- `workspaces/host-docker-internal_shannon-1790063197135/Security-Assessment-Report.md`

### PoC 脚本

- `workspaces/host-docker-internal_shannon-1790063197135/.shannon/scratchpad/brute_login.py`

## 对 Shannon 工作流的理解点

从这个 AUTH-01 可以看出 Shannon 的核心流程是：

1. pre-recon 先用源码建立安全地图。
2. recon 把源码地图和运行中的应用行为对齐，形成 attack surface map。
3. 专项 vuln agent 并行分析各类漏洞。注入分析只处理 injection；认证分析只处理 AuthN。
4. vuln agent 不直接证明完整利用，而是输出 exploitation queue。
5. exploit agent 按队列逐项主动验证，并在需要批量请求时委托 task agent 写脚本。
6. final report 会再做筛选、合并和重编号，所以分析阶段编号和最终报告编号可能不同。

AUTH-01 的关键不是“代码里出现了一个危险 sink”，而是“登录这个安全控制缺少 abuse defense”。这就是为什么它出现在 `vuln-auth` 和 `exploit-auth` 链路里，而不是 `vuln-injection` 链路里。
