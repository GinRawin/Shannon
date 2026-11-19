# Explore 克隆检索方法简介

## 定位

Explore 用**确定性 AST 结构化克隆检索**（`ast_structural_clone_v1`，schema v3）替代旧的「模型生成正则 + ripgrep 模板搜索」。

- 不调用模型，纯本地计算，可复现、零成本；
- 只做**检索**：命中只表示"代码结构长得像"，是否为漏洞由后续按类扩展分析判断；
- 目标为 Type-2（改名 / 换字面量）与 Type-3（少量语句子树的增删改）克隆，不做 Type-4 语义克隆。

旧的归一化 token 检索（`normalized_token_clone_v1`，schema v2）已不再作为生产默认，仅作为离线 baseline 保留：**只有显式设置** `SHANNON_EXPLORE_ALGORITHM` 为 `token` / `v2` / `normalized_token_clone_v1` 时才切回 v2；未设置、空值、未知值以及 `ast` / `v3` 一律走 AST 结构化检索 v3。

## 方法流程

1. **取种子**：取已验证且状态为"已利用"的漏洞代码位置（文件 + 行号），去重校验路径在仓库内、为普通文件、可读。
2. **选锚点**：用 Tree-sitter 解析记录行所在文件，把记录行定位到 AST 锚点，优先取 call / assignment / return 语句；记录行本身无语句时上下各放宽 2 行，一行存在多个语句时最多保留 3 个候选锚点，锚点不唯一时记录为 `ambiguous_anchors` 而不是猜一个。
3. **构造 sink-anchored forest**：以锚点完整语句为根，取其所在块内相邻兄弟语句（每侧 2 条），以及最多 3 级 `if` / loop / try / lambda 控制上下文，**绝不跨函数边界**；节点数低于 12 视为样本过短并跳过。
4. **结构归一化**：标识符与字面量统一折叠（`IDENTIFIER` / `LITERAL`），但保留 `CALL`、`IF`、`RETURN`、`AWAIT`、运算符、成员/下标访问与调用实参个数，并保留"带字段的父子边"顺序，因此改名与换字面量不改变结构，而父子/兄弟/嵌套关系的差异不会被抹平。
5. **提取特征并建索引**：抽取节点类型、带字段的父子边、深度 2/3 的子树形状、控制上下文，以及低权重的被调 API 标签，按反文档频率（IDF）加权后汇成共享倒排索引。
6. **召回初筛**：以 IDF 加权 Dice 系数给候选 forest 打分，`minRetrievalScore = 0.25` 以上进入精细匹配，每种子最多 100 个候选。
7. **有序树匹配与对齐定位**：对候选执行有序树/森林近似匹配（允许整棵语句子树的插入、删除、替换），要求树相似度达到 `minTreeSimilarity = 0.5` 且锚点必须映射成功；`match_line` 取自锚点映射到候选侧的真实可执行语句行号，不是函数首行/窗口首行/虚拟根行号。锚点无法映射时直接跳过并计入 `unmapped_anchors`。
8. **去重限额**：排除种子自身位置、同文件重叠命中与重复三元组；按分数、文件、行号稳定排序，逐种子交错输出后按上限截断（截断会标记 `truncated`，不静默丢候选）。

## 参数取值

| 类别 | 参数 |
|---|---|
| 匹配门槛 | 召回分 `minRetrievalScore 0.25`；树相似度 `minTreeSimilarity 0.5`；每种子锚点候选上限 `3` |
| 森林形状 | 兄弟半径 `2`；控制上下文深度 `3`；森林节点上限 `180`、下限 `12` |
| 特征权重 | 节点 `1`、边 `2`、深度 2 形状 `3`、深度 3 形状 `4`、上下文 `2`、API 标签 `1`（再乘 IDF） |
| 输出预算 | 种子 `30`、每种子精细命中 `10`、全局命中 `100`；每次匹配的候选 forest `100` |
| 扫描上限 | 文件 `5000`、单文件 `1 MB`、索引森林 `10 万`、单文件候选 `400` |
| 匹配预算 | 单对 DP 单元 `20 万`、单种子匹配操作 `1000 万` |
| 摘录 | 每条命中摘录上限 `800` 字符 |

超过任一扫描或匹配上限会置 `truncated: true`，候选不会被静默丢弃。

## 产物

- 检索结果 `explore_search_results.json`（schema v3，`algorithm: ast_structural_clone_v1`）：命中文件/行、候选起止行、分数、摘录，以及可选的 `ast_evidence`（召回分、树相似度、锚点置信度、种子/候选/映射节点数、插入/删除子树数、控制上下文是否变化、锚点是否映射）；
- 种子清单 `explore_seeds.json`：每个种子的语言、状态、锚点行、锚点候选数、森林节点数、上下文深度与命中数；
- 覆盖率报告 `explore_clone_coverage.json`：`verified / eligible / skipped / indexed / matched / truncated` 计数、按原因汇总的跳过统计、每种子明细，以及 `parse_failed_files`、`indexed_forests`、`retrieval_candidates`、`reranked_candidates`、`unmapped_anchors`、`ambiguous_anchors`、`matcher_budget_exceeded`、`parser_language_unsupported`；
- 人读摘要 `explore_deliverable.md`。旧的模板类产物会被删除。

## 下游使用

- **精确行准入**：扩展分析提交的危险点位置必须覆盖某条命中行，仅文件名相同不算；
- 相似度只是准入门槛，**不是漏洞证据**，必须回到完整路径、数据流、守卫与鉴权判断；
- 安全变体（同操作但加了归属/角色校验）会被作为候选返回，由扩展分析拒绝；
- 命中可"富集"已有发现，或以本类新编号提交为独立新候选，再走利用与记录流程；
- 扩展分析每个命中都要检查完整数据流，整个扩展只执行一轮，不递归回到 Explore。

## 范围与局限

- 语言：仅 JS/TS 家族（`.ts`、`.tsx`、`.mts`、`.cts`、`.js`、`.jsx`、`.mjs`、`.cjs`）与 Java；同语言匹配，JS/TS 与 Java 不互相匹配，其他语言按 `unsupported_language` 跳过；
- 能力：AST 结构相似 + 有序树匹配，无数据流/污点、无语义克隆，锚点不对应函数边界之外的语义；
- 判定：`tree_similarity` 是结构相似度，不是漏洞概率；
- 覆盖：大仓库会被上限截断，需检查 `truncated` 与覆盖率报告；解析失败（`parse_error`）与零相似候选是两种不同情形，前者单独计数。

## 离线测试

```bash
pnpm test:explore-ast            # AST v3 检索服务，覆盖 T01-T19
pnpm test:explore-ast-activity   # 真实 runExploreAgent Activity：默认 v3、显式 token=v2、种子门槛、工件提交与重跑幂等
pnpm test:explore-clone          # v2 token baseline
```
