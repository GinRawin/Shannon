# 下一步优化建议（最多 2 项）

> 每项写明：命中哪类漏检 / 为什么会改善 / 最小 PoC 如何证伪。
> 依据见 `diagnosis/diagnosis_summary.md` 与 `diagnosis/case_diagnosis.json`。

---

## 建议 A（最高优先，已实现）：为 Exploit 裁决增加 `false_positive` 出口，让假阳性不再被误报为 `unprocessed`

**命中漏检类型**：`pipeline_gap`（更正自 `budget_or_context`）。本批次 32/172 ≈ 19% 的 `unprocessed` 已核实为**逐条判定过的假阳性**，只是裁决没有结构化出口（详见 `diagnosis_summary.md` “发现 1（更正）”，32/32 逐条命中）。

**根因**：
- `add_exploit` 只接受 `exploited`/`blocked`，无 `false_positive`（`apps/worker/src/collectors/exploit-collector.ts`）。
- Prompt 让 agent 把 FP 写入 `workspace/<class>_false_positives.md`，但 `apps/worker/src` 无任何代码读取它（write-only）。
- 渲染器 `Unprocessed = 队列 − add_exploit`，于是 FP 裁决全部落进 `Unprocessed`。

**已实现修复**（2026-11-26）：
- `add_exploit` 新增 `status: "false_positive"`（必填 `reason`；可选 `vulnerable_location`/`what_we_tried`/`notes`），作为终结裁决，不再计入 `Unprocessed`。
- 渲染器新增 `## False Positives (Proven Not Exploitable)` 段（`apps/worker/src/services/exploit-renderer.ts`）；FP 不进入 Record/报告/重放，也不参与重编号（`apps/worker/src/services/renumber-core.ts`）。
- 6 个 `apps/worker/prompts/exploit-*.txt` 改为要求 agent 用 `add_exploit(status="false_positive", reason=...)` 记录 FP；跟踪文件降级为可选补充。
- 日志指标新增 `falsePositive`（`apps/worker/src/temporal/activities.ts`）。

**最小 PoC（可证伪）**：
1. 取 `cp-dev` run（`…shannon-1795606717356`），用新代码重跑 authz Exploit，或离线把 `authz_false_positives.md` 中 13 项 FP 转成 `add_exploit(status="false_positive", ...)`。
2. 预期：`authz_exploitation_evidence.md` 出现 `## False Positives (Proven Not Exploitable)`，且 `## Unprocessed Vulnerabilities` 不再出现 `AUTHZ-07..13/16..22`。
3. 反例：若某项实为可在线利用而被误判 FP，重跑时应能转为 `exploited`（说明是判定错误而非本次出口修复的问题）。

**验收判定**：`Unprocessed Vulnerabilities` 只应剩**确实未产生任何裁决**的候选；即 `queued - exploited - blocked - false_positive == 真实未裁决数`。

## 建议 B：修复 Record 重放计划的生成与校验（保住已成功利用的真实漏洞）

**命中漏检类型**：`record_failed`。本批次命中 **7** 项——Exploit 已取得运行时影响证据、`review_verdict=retry` 且明示“not a false positive”，却因**计划格式缺陷**被剔除出报告：
ai-media `AUTH-02`/`AUTHZ-13`/`AUTHZ-26`、cp-dev `AUTH-01`/`AUTH-02`/`XSS-01`、imwl `XSS-03`。

**代码级归因**：见 `diagnosis/record_stage_analysis.md`（4 个代码缺陷 + 1 个过窄设计 + 失效的 review→retry 闭环，含行号与最小复现）。

**根因（逐条可复现）**：
| 缺陷 | 触发 finding | 修法 |
|---|---|---|
| 变量命名规则：“Extracted variables must have uppercase names distinct from operator variables” | ai-media AUTH-02；cp-dev AUTH-01/02 | 生成阶段即用大写且不与算子/内建名冲突的变量名，并在提交前校验 |
| 计划断言内联“认证物料”literal → `Replay plan contains literal authentication material` | ai-media AUTHZ-26 | 断言只用结构化/非标识串，禁止内联账号、token、密钥、cookie |
| HTTP 动词与真实接口不一致（计划 `POST`、接口 `GET`） | ai-media AUTH-02 | 生成 setup 步骤时以 inventory 的 method 为准，提交前交叉校验 |
| 雪花 ID 精度丢失 + 绝对计数断言不稳定（`{"data":9}`） | ai-media AUTHZ-13 | 64 位 ID 全程字符串化；用“新增标记”相对断言替代绝对计数 |
| 纯浏览器 / URL-hash 驱动型 XSS 缺 `complete_http_packet`、缺 JS 执行回执 | cp-dev XSS-01；imwl XSS-03 | 为 hash/browser-only sink 合成承载该 SPA 壳的最小 HTTP 包；产出可验证的 JS 执行回执 |

**为什么能改善**：这 7 项**已经是真实漏洞**，损失纯属重放计划工程缺陷（约占 exploited 的 10%）。修复后**直接转为已报告**，是“无损回收”。

**最小 PoC（可证伪）**：取 `record-failures.json` 中这 7 项，**手工**按上表修正 `revised_replay_plan` / `revised_browser_replay`（或修正生成器规则），重跑 Record：
- 若有任一项在修正后仍无法通过、且原因是“漏洞不存在/被安全控制阻止” → 该项不属于本类漏检，需剔除。
- 其余应通过并进入报告。

**验收判定**：`record_report_exclusions.json` 中“not a false positive”类条目应清零，或每条都带有明确的“已修正仍失败”的证据与分类。

---

## 不建议现在做的事（依据本批次证据）

- **不建议优先扩检测/知识库**：3 个 run 已产出 49/60/63 条候选队列，未见“定位不到”的系统性证据；当前矛盾在**验证完成度**（172 入队仅 69 得到 exploited 裁决）。
- **不建议据本批次下工具优劣结论**：无受控 A/B、工具调用不一致、缺 `index_found`（见 `tool_ablation.md`）。
