# StreamLens 明鉴 源代码交付说明

本文说明参赛提交包中的源代码结构、运行入口和主要实现边界。

## 目录结构

| 目录或文件 | 作用 |
|---|---|
| `src/main.py` | FastAPI 服务、SSE 流式接口、Web 路由和运行入口 |
| `src/agents/agent.py` | LangChain Agent、工具注册、系统提示词和案件对话路由 |
| `src/tools/prompt_tools.py` | Prompt 规则、熵分布、语义结果融合，以及解释、修复、复检 |
| `src/tools/entropy_detector.py` | 字符级熵代理、窗口信号和 Entropy-CPD 变点检测 |
| `src/tools/pcap_tools.py` | PCAP 预检、协议解析、规则路和行为路检测 |
| `src/tools/adversary_service.py` | Prompt 和 PCAP 红蓝攻防实验服务 |
| `src/tools/challenge_tools.py` | Token/PCAP 侦探挑战逻辑 |
| `src/tools/case_store.py` | 案件、消息、证据和审计事件归档 |
| `src/tools/knowledge_tool.py` | 安全知识库检索 |
| `src/tools/report_tool.py` | 调查报告生成 |
| `web/` | 单页 Web 工作台和流式消息渲染 |
| `assets/` | 知识库、冻结样本和教学用 PCAP |
| `config/agent_llm_config.json` | 模型、温度、超时和系统提示词配置 |
| `scripts/expanded_eval.py` | 240 条确定性 Prompt 扩展评测脚本 |

## Agent 工具

配置文件登记 11 个核心安全工具，包括 Prompt 检测五工具、PCAP 检测四工具、知识检索和报告生成。运行时还保留挑战、评测、流量画像和最近任务等辅助工作区工具。

## 安全边界

检测结果必须引用真实工具证据。Entropy-CPD 只作为辅助证据，语义判断可能误报，PCAP 加密流量和未知攻击不作超范围承诺。高影响处置需要人工授权。

## 凭据

`config/credentials.env.example` 仅为配置模板。真实模型 Key 应写入未纳入版本控制的 `config/credentials.env` 或部署环境变量，不得提交到仓库或放入前端代码。
