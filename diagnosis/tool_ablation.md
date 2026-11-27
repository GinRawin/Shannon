# 工具消融（`find_security_candidates`）— 2026-11-25 批次

## 结论（先给判定）

**本批次无法给出工具增量的 A/B 检出率或开销对比。** 依据 `toBeCheck.md` §6：缺少数据时必须注明缺失项，**不得填造数值**。

原因：
1. 未做受控 A/B（无“关闭工具 / 启用工具”的同条件重复运行记录）。
2. 工具调用本身在 3 个 run 中**不一致**，天然不具备可比性。
3. 工具的底层索引命中信息（`index_found`）在工件中不可见。

## 实测调用情况

工具定义见 `docs/java-security-candidates.md`：仅注册给 `pre-recon`/`recon`，结果写入
`<target>/.shannon/scratchpad/security-candidates/<vulnerability_type>[_<function>][_page-<hash>].txt`。

| run | `find_security_candidates` 调用 | 生成的候选文件 | 覆盖的漏洞类型 |
|---|---:|---|---|
| ai-media | **0** | 无 | —（完全未使用） |
| cp-dev | 6 | `injection.txt` `authz.txt` `ssrf.txt` `ssrf_page-796fba28.txt` | 缺 auth / xss |
| imwl | 3 | `injection.txt` `ssrf.txt` `ssrf_page-7fc836f1.txt` | 缺 auth / authz / xss |

证据：`grep -r find_security_candidates workspaces/<run>/.shannon/agents/` 与
`ls workspaces/<run>/.shannon/scratchpad/security-candidates/`。

## `toBeCheck.md` §3 三值分离的可观测性

| 维度 | 本批次可观测？ | 说明 |
|---|---|---|
| `index_found`（工具底层全量索引是否命中真值位置） | ❌ unknown | 工具仅回传候选位置，无“真值命中”记录；亦无离线真值列表可对拍 |
| `tool_returned`（本次查询是否返回该候选） | ⚠️ 部分 | 仅能确认写了哪些 `security-candidates/*.txt`，未记录每次查询的返回集合 |
| `agent_consumed`（Agent 后续是否实际使用） | ❌ unknown | 无候选位置 → 队列条目的直接引用；`recon_deliverable.md`/队列与候选文件的对应关系未落盘 |

因此无法区分“工具没提高检出率”与“工具提高效率”——按 `toBeCheck.md`，这两者不可相互否定。

## 若要做真实 A/B，需补齐的最小记录

- 每次运行的 `shannon_commit` / 目标 `commit` / 模型采样参数 / 总预算（本批次 `session.json` 有 run 元数据，但**无 Shannon commit、无目标 commit、无采样参数**）。
- 每次 `find_security_candidates` 调用的入参（`vulnerability_type`/`limit`/`function_name`/`cursor`）与返回（`status`/`results_count`/`next_cursor`）。
- 候选文件位置 → 分析队列条目 → collector 条目的映射（用于 `incremental_location_recall`）。
- 离线真值标签（不得注入 Agent 上下文）。
- 同条件多轮重复运行（报告波动，不凭单次断言）。

## 旁证（不构成 A/B，仅记录）

- 启用工具的 cp-dev/imwl，其**入队候选数**并不低于未启用工具的 ai-media（60/63 vs 49），但受“Exploit 未跑完队列”影响，`record_verified` 反而更低（11/36/20）。这说明**瓶颈不在工具供给候选**，而在候选的验证完成度（详见 `diagnosis_summary.md`）。
