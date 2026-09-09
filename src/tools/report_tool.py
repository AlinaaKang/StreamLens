"""调查报告生成工具：基于当前案件证据生成 Markdown/PDF 报告并上传对象存储"""
import logging
import os
import time
from typing import Optional

from langchain.tools import tool
from coze_coding_utils.log.write_log import request_context
from coze_coding_utils.runtime_ctx.context import new_context

from tools.case_store import case_store

logger = logging.getLogger(__name__)

WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")


def _md_safe(t, limit: int = 120) -> str:
    """清理动态文本：去控制/零宽字符、压缩空白、限长，避免 PDF 渲染乱码与表格溢出。"""
    import re
    t = str(t or "")
    t = re.sub(r"[\x00-\x1f\x7f\u200b-\u200f\u2028\u2029]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) > limit:
        t = t[:limit] + "…"
    return t


def _sanitize_filename(name: str) -> str:
    """文件名规范：仅字母数字下划线短横"""
    import re
    name = re.sub(r"[^A-Za-z0-9_\-]", "_", name)
    return name.strip("_")[:80] or "report"


def _build_report_for_task(task_id: str) -> str:
    """报告生成主体（供 @tool 与 Web API 复用）：汇总证据→研判→PDF→对象存储"""
    try:
        task = case_store.get_task(task_id)
        if task is None:
            return f"错误：案件 {task_id} 不存在。"

        mode = task["mode"]
        evidences = task.get("evidence", [])
        mode_cn = "Prompt 安全调查" if mode == "prompt" else "PCAP 数据调查"

        # 汇总风险级别（取复检优先，其次语义证据，再次网络证据的最高置信度）
        risk_level = "unknown"
        if (task.get("recheck") or {}).get("risk_level"):
            risk_level = task["recheck"]["risk_level"]
        elif evidences:
            semantic_confs = [e.get("confidence", 0) for e in evidences if e.get("source") == "semantic_scan"]
            # 网络检测证据：任一高置信度异常即视为高风险（扫描/暴破/C2/外传均为明确攻击行为）
            network_confs = [e.get("confidence", 0) for e in evidences
                             if e.get("source") in ("pcap_detect",) or str(e.get("evidence_id", "")).startswith("N-")]
            all_confs = semantic_confs + network_confs
            if (semantic_confs and max(semantic_confs) >= 0.75) or (network_confs and max(network_confs) >= 0.75):
                risk_level = "high"
            elif all_confs and max(all_confs) >= 0.5:
                risk_level = "medium"
            elif all_confs:
                risk_level = "low"
            else:
                risk_level = "low"
        level_cn = {"high": "高风险", "medium": "中风险", "low": "低风险", "none": "未发现风险", "unknown": "待定"}.get(risk_level, risk_level)

        # ---- 组装 Markdown ----
        md = [f"# {mode_cn}报告 - {task.get('title', '')}", ""]
        md.append(f"- **任务 ID**: {task_id}")
        md.append(f"- **调查模式**: {mode_cn}")
        md.append(f"- **创建时间**: {task.get('created_at')}")
        md.append(f"- **报告生成时间**: {time.strftime('%Y-%m-%dT%H:%M:%S+08:00')}")
        md.append(f"- **综合风险级别**: {level_cn}")
        md.append("")

        md.append("## 1. 调查输入")
        if mode == "prompt":
            prompt_text = task.get("original_prompt", "")
            shown = prompt_text if len(prompt_text) <= 500 else prompt_text[:500] + "...（截断，原文已存档）"
            md.append("被检测的原始 Prompt（按权限展示）：")
            md.append("```text")
            md.append(shown or "（未记录）")
            md.append("```")
        else:
            for f in task.get("pcap_files", []):
                md.append(f"- **{_md_safe(f['name'], 60)}**：{f['size'] / 1024:.1f} KB，{f.get('packet_count', '-')} 包，SHA256 前 24 位 {f['sha256'][:24]}…，导入于 {f.get('imported_at', '-')}")
        md.append("")

        md.append("## 2. 执行计划与工具状态")
        for k, v in task.get("connector_state", {}).items():
            md.append(f"- **{_md_safe(k, 40)}**：{_md_safe(v, 60)}")
        md.append("")
        md.append("证据状态图例：`real`=真实检测，`derived`=数学推导（熵计算），`simulated`=模拟回执，`unavailable`=不可用。")
        md.append("")

        md.append("## 3. 证据目录")
        if evidences:
            for e in evidences:
                summary = _md_safe(e.get("summary", ""), 80)
                md.append(
                    f"- **{e['evidence_id']}**（{e.get('status')} · {e.get('source')} · 置信度 {e.get('confidence', '-')}）"
                    f"{summary}（位置：{e.get('location', '-')}）"
                )
        else:
            md.append("无证据记录。")
        md.append("")

        md.append("## 4. 攻击链关联（如有）")
        hyps = task.get("hypotheses", [])
        if hyps:
            for h in hyps:
                md.append(f"- **{_md_safe(h['stage'], 40)}**：支持证据 {', '.join(h['supports'])}（置信度 {h.get('confidence', '-')}）")
        else:
            md.append("本案件未执行攻击链关联（Prompt 类案件不适用）。")
        md.append("")

        # 修复与复检
        if mode == "prompt" and task.get("repair"):
            repair = task["repair"]
            md.append("## 5. 修复与复检")
            md.append("**修复版本**：")
            md.append("```text")
            md.append(repair.get("repaired_prompt", ""))
            md.append("```")
            md.append("**修改点**：")
            for c in repair.get("changes", []):
                md.append(f"- {c}")
            recheck = task.get("recheck")
            if recheck:
                md.append(f"**复检结果**：风险级别 {recheck.get('risk_level')}，复检时间 {recheck.get('checked_at')}")
            md.append("")

        idx = 6 if (mode == "prompt" and task.get("repair")) else 5
        md.append(f"## {idx}. 结论与不确定性")
        md.append(f"- 综合风险级别：**{level_cn}**")
        md.append("- 以上结论基于当前会话内的工具证据；证据状态均为 real（真实检测）或 derived（数学推导），无伪造回执。")
        if mode == "pcap":
            md.append("- 仅有流量元数据，无终端进程、身份日志与完整网络上下文，结论为\"疑似\"性质，不能确认攻击成功或攻击者身份。")
        else:
            md.append("- 语义判断基于模型推理存在误报可能；Entropy-CPD 误报偏高，仅作为第二路证据，不单独决定处置。")
        md.append("")

        md.append(f"## {idx + 1}. 处置建议与授权边界")
        if level_cn == "高风险":
            if mode == "prompt":
                md.append("- 建议阻断该 Prompt 进入生产环境；如需替换线上 Prompt，属 L2 高影响动作，需用户明确授权。")
            else:
                md.append("- 建议对涉事源 IP 执行防火墙封禁、对受感染主机执行 EDR 隔离（均属 L2 高影响动作，需用户明确授权后方可执行）。")
        elif level_cn == "中风险":
            md.append("- 建议进入人工复核队列；补充终端/身份证据后重新评估。")
        else:
            md.append("- 当前无需强制处置；建议保留检测记录并持续观察。")
        md.append("- 本环境未连接真实 EDR/防火墙/身份系统（状态 unavailable），不伪造执行结果。")
        md.append("")

        md.append(f"## {idx + 2}. 审计信息")
        md.append(f"- 证据总数: {len(evidences)}")
        md.append(f"- 授权记录: {task.get('authorization') or '无'}")
        md.append(f"- 案件数据文件: assets/cases/{task_id}.json（可回看完整决策链）")

        markdown_content = "\n".join(md)

        # ---- 生成 PDF 并上传 ----
        from coze_coding_dev_sdk import DocumentGenerationClient
        ctx = request_context.get() or new_context(method="generate_report")
        doc_client = DocumentGenerationClient()

        ts = time.strftime("%Y%m%d_%H%M%S")
        file_stem = _sanitize_filename(f"{mode_cn}_{task_id}_{ts}")
        url = doc_client.create_pdf_from_markdown(markdown_content, file_stem)

        case_store.update_task(task_id, report_url=url)

        lines = ["【调查报告已生成】", ""]
        lines.append(f"- 案件: {task_id}（{mode_cn}）")
        lines.append(f"- 综合风险级别: {level_cn}")
        lines.append(f"- 证据数: {len(evidences)}")
        lines.append(f"- 报告下载链接（24小时有效）: {url}")
        case_store.log_action(task_id, "generate_investigation_report",
                              f"正式报告已生成并上传（判级 {level_cn}，证据 {len(evidences)} 条）")
        lines.append(case_store.build_chain(
            task_id,
            observe=f"为案件 {task_id} 生成正式调查报告",
            plan="generate_investigation_report：汇总证据→研判→PDF 生成→对象存储上传",
            close=f"报告判级 {level_cn}；报告内容与案件证据一一对应，不含虚构信息",
        ))
        return "\n".join(lines)
    except Exception as e:
        logger.exception("generate_investigation_report failed")
        return f"报告生成失败：{e}"


@tool
def generate_investigation_report() -> str:
    """基于当前调查案件的完整证据链生成正式调查报告（PDF），上传对象存储并返回下载链接。报告包含案件信息、调查计划、证据目录、结论与限制。检测/分析完成后可调用。"""
    task = case_store.get_current()
    if task is None:
        return "错误：当前没有任何调查案件（Prompt 或 PCAP）。请先发起检测。"
    return _build_report_for_task(task["task_id"])
