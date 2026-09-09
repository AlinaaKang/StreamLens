# StreamLens 明鉴

面向 AI 安全的 Prompt 与 PCAP 双轨调查智能体。

StreamLens 明鉴把自然语言对话、大模型 Agent、本地安全检测引擎和可审计案件记录放在同一个工作流中。用户可以提交一段 Prompt 或一个抓包文件，智能体会根据当前模式选择检测工具，返回证据、解释、下一步建议，并在需要时生成修复方案、复检结果和调查报告。

> **核心原则**：大模型负责理解、规划和解释；本地引擎负责检测和生成证据；固定策略负责融合与授权边界。模型不能虚构 Packet、检测结果或已经执行的外部处置。

## 能做什么

### 安全对话

- 普通问题直接自然语言回答，不因内容看似可疑而自动触发检测；
- 已有案件中的“为什么”“哪里异常”“结论可靠吗”等追问，读取当前案件证据和历史消息；
- 只有明确的检测、复检、报告或控制指令才调用对应工具；
- SSE 流式输出，前端同时展示回答、工具状态、证据和下一步建议。

### Prompt 安全检测

一次分析同时运行三路证据：

1. 规则标记：已知注入、越权、分隔符伪造和编码特征；
2. Entropy-CPD：借鉴公开熵异常与变化点检测研究，以字符级统计近似 token 分布并定位突变起点；
3. 语义扫描：通过 OpenAI 兼容接口调用专用语义模型，输出 Safe / Controversial / Unsafe。

三路结果进入固定融合策略：语义危险进入拦截，语义争议或纯统计异常进入人工复核，全部正常才放行。风险轨道会将异常起点映射到 token/字符区间，便于查看原文片段和证据编号。反事实工具会截断异常点前缀重新检测，验证定位是否成立。

### PCAP 调查

- 预检文件格式、大小、哈希和重复提交；
- 使用 `dpkt` 逐包解析时间、协议、方向、端点和载荷特征；
- 规则路覆盖端口扫描、SSH 暴力破解、C2 心跳、数据外传、SQL 注入、DNS 隧道、Web 攻击载荷、SYN 洪泛和 ARP 欺骗；
- 行为路使用端口接触广度、连接速率、周期性、上行字节和 DNS 标签分布等统计信号；
- 融合路保留规则/行为来源、置信度、时间范围和 Packet 定位，并可关联 ATT&CK 阶段。

PCAP 检测是网络证据分诊，不运行 Prompt 的 Entropy-CPD，也不恢复 Prompt 内容。0day、加密流量解密和完整 APT 渗透链不属于已验证覆盖范围。

### 攻防实验与侦探挑战

- Prompt 红队提交对抗 Prompt，真实走检测管线；蓝队对样本判断风险类型和级别；
- PCAP 实验使用固定或参数化教学流量，Packet 证据与检测阈值真实对应；
- Token 侦探挑战让用户根据语义结果和 CPD 轨道标记异常起点，并用反事实复检验证；
- 教学实验与真实案件分离，实验真值不会写入用户调查案件。

## 架构

```text
浏览器 Web 工作台
    │ REST / SSE
FastAPI 服务层（src/main.py）
    │
LangChain Agent（src/agents/agent.py）
    ├── Prompt：规则标记 + Entropy-CPD + 语义扫描
    ├── PCAP：规则路 + 行为路 + 融合路
    ├── 知识检索：五类安全知识材料
    └── 案件/报告：证据归档、审计、修复复检、报告生成
```

Agent 配置文件登记 11 个核心工具：Prompt 五个、PCAP 四个、知识检索和报告生成。挑战、评测和任务恢复等工作区功能作为辅助工具保留。

## 快速运行

### Windows

要求 Python 3.12+。双击 `run_windows.bat`，脚本会同步依赖并优先使用项目 `.venv` 启动服务，然后打开：

```text
http://127.0.0.1:5000/web
```

自然语言对话需要配置模型服务：

```text
copy config/credentials.env.example config/credentials.env
```

填写 `OPENAI_API_KEY`，可选填写 `OPENAI_BASE_URL` 和 `OPENAI_MODEL`。密钥只放在服务端环境，不要提交到 Git。

### Linux / macOS

```bash
bash start.sh
```

手动启动：

```bash
uv sync
export COZE_PROJECT_TYPE=agent
export COZE_PROJECT_ENV=DEV
export COZE_WORKSPACE_PATH=/absolute/path/to/StreamLens
export PYTHONPATH=/absolute/path/to/StreamLens/src
python src/main.py -m http -p 5000
```

访问 `http://127.0.0.1:5000/web`。启动脚本不包含真实凭据。

## 测试

### 本地规则与分布信号扩展评测

```bash
.venv/Scripts/python.exe scripts/expanded_eval.py
```

固定种子生成 240 条 Prompt 变体，并解析 5 个教学 PCAP。该测试不调用 LLM，只用于本地信号消融和回归。

### 三路真实语义端到端评测

```bash
.venv/Scripts/python.exe scripts/semantic_e2e.py \
  --api-url https://<your-streamlens-host> \
  --required \
  --output tmp/semantic_e2e_report.json
```

该脚本调用 `/web/api/prompt/analyze`，检查规则字段、`cpd_status`、`semantic_status`、融合风险级别和最终动作。没有可用模型服务时会标记 `semantic_unavailable`；`--required` 会让测试失败，防止把降级状态误当作通过。

当前线上合成冒烟集结果：9 条样本全部三路执行，4 条攻击全部高风险拦截，4 条良性全部放行，1 条边界样本安全放行。样本量较小，只能作为 E2E 冒烟结果，不代表未知攻击的泛化准确率。

更多测试方法、样本构成和限制见 [`docs/02-测试文档-StreamLens.md`](docs/02-测试文档-StreamLens.md)。

## 目录结构

```text
src/
  main.py                         FastAPI、SSE 和 Web API
  agents/agent.py                 Agent 编排、模式路由和工具注册
  tools/prompt_tools.py           Prompt 三路检测、融合、修复和复检
  tools/entropy_detector.py       字符统计、NLL 和 Entropy-CPD
  tools/pcap_tools.py             PCAP 预检、规则/行为/融合检测
  tools/knowledge_tool.py         安全知识检索
  tools/case_store.py             案件、消息、证据和审计归档
  tools/report_tool.py             调查报告生成
  tools/adversary_service.py      双轨红蓝攻防
  tools/challenge_tools.py        Token/PCAP 侦探挑战
web/                               单页工作台
assets/knowledge/                  五类知识材料
assets/challenge/                 冻结挑战样本与基线
assets/test_data/                 5 个合成教学 PCAP
scripts/expanded_eval.py          本地扩展评测
scripts/semantic_e2e.py           三路语义 E2E 评测
config/agent_llm_config.json      Agent 模型与系统提示词
config/credentials.env.example    凭据模板
docs/                             比赛设计、测试、总结和部署文档
dist/StreamLens明鉴_答辩PPT.pptx    答辩 PPT
```

## 可信边界

- Entropy-CPD 的理论思想借鉴公开研究；本项目贡献是工程集成、异常起点定位、可视化、证据化和反事实复核；
- 字符级熵是 token 熵的可部署近似，不能等同于模型内部真实 token 概率；
- 语义模型可能误报或漏报，PCAP 周期性/加密流量也可能产生弱 C2 候选；
- 统计异常不能单独触发高影响处置；封禁、隔离、生产 Prompt 替换等动作必须人工授权；
- 当前未接入真实防火墙或 EDR 时，不会伪造“已执行”结果。

## 比赛材料

- [`01-设计文档-StreamLens.md`](docs/01-设计文档-StreamLens.md)
- [`02-测试文档-StreamLens.md`](docs/02-测试文档-StreamLens.md)
- [`03-总结报告-StreamLens.md`](docs/03-总结报告-StreamLens.md)
- [`04-合规声明-StreamLens.md`](docs/04-合规声明-StreamLens.md)
- [`05-源代码交付说明-StreamLens.md`](docs/05-源代码交付说明-StreamLens.md)
- [`07-部署运行手册-StreamLens.md`](docs/07-部署运行手册-StreamLens.md)
- [`08-答辩PPT提纲-StreamLens.md`](docs/08-答辩PPT提纲-StreamLens.md)
- [`10-演示脚本与分镜-StreamLens.md`](docs/10-演示脚本与分镜-StreamLens.md)

本仓库不新增独立的数据集与样本清单。五分钟演示视频和审核通过的官方报名表需要在提交前由参赛团队补入。

## License and attribution

本项目中的第三方依赖遵循各自许可证。公开研究思想、知识材料和外部样本的来源与适用范围以仓库中的知识文档、测试文档及其原始许可为准。参赛提交时请根据赛事要求补充团队署名、许可证和授权证明。
