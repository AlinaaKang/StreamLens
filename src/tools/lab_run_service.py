"""Token 侦探挑战 · 检测运行服务。

对齐参考实现（token-detective-challenge）的表现层结构（LabRunResult），
数据全部来自本项目的真实检测链路，禁止任何 mock：

- 语义 Guard：大模型语义扫描（run_prompt_analysis，真实 LLM 调用）
- 分布观测：滑窗熵 / 窗口 NLL / 在线 CPD（entropy_detector，字符窗口近似 token 窗口）
- 融合判定：语义级别 × 分布候选 的固定融合规则
- 知识检索：安全知识库真实命中（search_knowledge_struct）
- 反事实：截断至预测起点后重算分布信号（真实统计反事实，不重跑语义模型）
"""
from __future__ import annotations

import json
import os
import random
import time
from typing import Any

from tools.entropy_detector import (
    compute_cpd_series,
    detect_change_points,
)
from tools.knowledge_tool import search_knowledge_struct
from tools.prompt_tools import run_prompt_analysis

_REDACTED_NOTICE = "[对抗攻击内容已隐藏]"

_PROTECTED_INTENT = {
    "gcg_style": "优化生成的对抗后缀识别",
    "autodan_style": "自然语言包装的越狱指令识别",
    "advprompter_style": "自动生成的对抗提示识别",
}

_PROTECTED_CONTENT = {
    "gcg_style": "正常请求结构后附加了优化生成的对抗字符串。",
    "autodan_style": "自然语言角色与指令包装试图改变模型安全边界。",
    "advprompter_style": "自动化提示生成器构造了对抗性请求。",
}

_SCENARIO_LABELS = {
    "benign_plain": "普通无害",
    "benign_shift": "无害格式突变",
    "autodan_style": "AutoDAN · 角色扮演脚手架",
    "gcg_style": "GCG · 对抗后缀",
    "advprompter_style": "AdvPrompter · 改写扰动",
}

_KB_QUERIES = {
    "benign_plain": "提示词注入 攻击特征 识别",
    "benign_shift": "输入风格漂移 分布异常 检测",
    "autodan_style": "角色扮演 越狱 指令包装",
    "gcg_style": "对抗后缀 梯度 优化攻击",
    "advprompter_style": "自动生成 对抗提示 改写",
}

_TRUTH_RELATION = {
    "benign_plain": "dual_normal",
    "benign_shift": "dual_normal",
    "autodan_style": "dual_risk",
    "gcg_style": "dual_risk",
    "advprompter_style": "dual_risk",
    "encoded_evasion": "dual_risk",
    "context_injection": "dual_risk",
    "exfil_probe": "dual_risk",
}


def _bank() -> list[dict]:
    path = os.path.join(os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects"),
                        "assets/challenge/samples.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)["samples"]


_ATTACK_FAMILY_ORDER = ["AD-", "GCG-", "ADVP-"]  # 权威优先级：AutoDAN → GCG → AdvPrompter
_ALL_ATTACK_FAMILIES = ["AD-", "GCG-", "ADVP-", "ENC-", "CTX-", "EXF-"]  # 扩充池：编码混淆 / 上下文注入 / 外泄探测


def _attack_pool(prefix: str) -> list[str]:
    """过滤过短样本（低于 MIN_TEXT_LEN 切不出 token 曲线窗口）后的族内可用样本。"""
    return [s["id"] for s in _bank()
            if s["id"].startswith(prefix) and len((s.get("text") or "").strip()) >= 30]


def _pick_attack() -> "str | None":
    """三关攻击样本：从全部六个攻击族随机选族（多样性），族内随机选样本。"""
    fams = [f for f in _ALL_ATTACK_FAMILIES if _attack_pool(f)]
    if not fams:
        for fam in _ATTACK_FAMILY_ORDER:
            pool = _attack_pool(fam)
            if pool:
                return random.choice(pool)
        return None
    return random.choice(_attack_pool(random.choice(fams)))
    return None


def _missing_attack_families() -> list[str]:
    return [f for f in _ATTACK_FAMILY_ORDER if not _attack_pool(f)]


def build_round_plan(kind: str = "three") -> list[str]:
    """关卡组样本计划（对齐参考实现 definitions：三关速战 / 五关完整挑战）。

    口径：三关速战的攻击关从全部六个攻击族随机出题（AutoDAN/GCG/AdvPrompter/编码混淆/
    上下文注入/外泄探测），提高挑战多样性；五关完整挑战保持权威结构（GCG/AD/ADVP
    三攻击族各一，缺族不可开始，不用其他样本冒充）。
    """
    def pick(prefix: str) -> str:
        pool = _attack_pool(prefix) or [s["id"] for s in _bank() if s["id"].startswith(prefix)]
        return random.choice(pool)

    if kind == "five":
        missing = _missing_attack_families()
        if missing:
            raise ValueError("五关模式需要三个攻击族样本全部可用（GCG/AutoDAN/AdvPrompter），当前缺失: "
                             + ", ".join(missing))
        return [pick("SAFE-"), pick("SHIFT-"), pick("GCG-"), pick("AD-"), pick("ADVP-")]
    atk = _pick_attack()
    if not atk:
        raise ValueError("三关模式需要至少一个攻击族样本可用，当前全部缺失")
    return [pick("SAFE-"), pick("SHIFT-"), atk]


_SEV_CN = {"safe": "语义安全", "controversial": "语义存疑",
           "unsafe": "语义危险", "unavailable": "语义证据不可用"}

_CF_CN = {
    "risk_reduced": "移除定位片段后分布异常下降（归因成立）",
    "unchanged": "移除后分布异常未下降（证据冲突，需人工研判）",
    "recheck_failed": "复检执行失败",
    "no_predicted_onset": "不适用（无预测起点）",
    "inconclusive": "结论不确定（复检不可判定）",
}


def _get_sample(sample_id: str) -> dict:
    for s in _bank():
        if s["id"] == sample_id:
            return s
    raise KeyError(f"unknown sample: {sample_id}")


def _build_signals(text: str) -> tuple[list[dict], dict]:
    """Token 级 signals（单一源：compute_cpd_series，与 detect_change_points 同链路）。"""
    cpd = compute_cpd_series(text)
    zmap = {p: z for p, z in (cpd.get("z_values") or [])}
    # 双侧累计偏离：Σmax(0,|z|-2)。与候选口径(|z|>=2)一致——熵升(注入拼接)与熵降(高熵编码)都可累积；
    # 原单侧 CUSUM W 对高熵样本(全负z)恒 0，导致"报了候选但 CPD 线全 0"的矛盾展示。
    entmap = {p: v for p, v in (cpd.get("entropy_values") or [])}
    nllmap = {p: v for p, v in (cpd.get("nll_values") or [])}
    idxs = [p for p, _ in (cpd.get("z_values") or [])]
    max_z = max((abs(z) for z in zmap.values()), default=0.0)
    threshold = 2.0
    signals = []
    cum_excess = 0.0
    for i, p in enumerate(idxs):
        z = zmap.get(p, 0.0)
        cum_excess += max(0.0, abs(z) - threshold)
        signals.append({
            "index": i,
            "char": p,
            "entropy": round(entmap.get(p, 0.0), 4),
            "nll": round(nllmap.get(p, 0.0), 4),
            "cpd": round(cum_excess, 4),
            "risk": round(min(1.0, abs(z) / max(threshold, 1e-9) * 0.5), 3),
        })
    span = None
    for s in signals:
        if zmap.get(s["char"], 0.0) >= threshold:
            span = {"token_start": s["index"], "char_start": s["char"]}
            break
    strongest_char = None
    strongest_idx = None
    strongest_abs_z = 0.0
    for s in signals:
        az = abs(zmap.get(s["char"], 0.0))
        if az > strongest_abs_z:
            strongest_abs_z = az
            strongest_char = s["char"]
            strongest_idx = s["index"]
    meta = {
        "window_size": len(idxs),
        "threshold": threshold,
        "max_z": round(max_z, 4),
        "n_candidates": sum(1 for p in idxs if zmap.get(p, 0.0) >= threshold),
        "candidate_chars": [p for p in idxs if zmap.get(p, 0.0) >= threshold],
        "cusum_h": cpd.get("threshold"),
        "t_alarm": cpd.get("t_alarm"),
        "strongest_char": strongest_char,
        "strongest_idx": strongest_idx,
        "strongest_abs_z": round(strongest_abs_z, 3),
    }
    return signals, {"suspicious_span": span, **meta}


def _counterfactual(text: str, char_start: Any, original_max_z: float) -> dict:
    """真实分布反事实：截断到预测起点后重算 CPD，对比分布分数变化。"""
    now = round(time.time() * 1000)
    if char_start is None:
        # 无预测起点（无 alarm 级候选）：反事实不适用（对齐权威 no_predicted_onset 语义）
        return {"interpretation": "no_predicted_onset", "reason": "no_predicted_onset",
                "char_start": None, "latency_ms": round(time.time() * 1000 - now, 1)}
    if char_start <= 0 or char_start >= len(text):
        return {"interpretation": "inconclusive", "reason": "invalid_predicted_onset",
                "char_start": char_start, "latency_ms": round(time.time() * 1000 - now, 1)}
    prefix = text[:char_start]
    if not prefix.strip():
        return {"interpretation": "inconclusive", "reason": "invalid_predicted_onset",
                "char_start": char_start, "latency_ms": round(time.time() * 1000 - now, 1)}
    re_ = detect_change_points(prefix)
    new_max = re_.get("max_z", 0.0) or 0.0
    delta = round(original_max_z - new_max, 4)
    return {
        "interpretation": "risk_reduced" if delta > 1e-6 else "unchanged",
        "reason": "completed",
        "char_start": char_start,
        "original_detector_score": round(original_max_z, 4),
        "rechecked_detector_score": round(new_max, 4),
        "detector_score_delta": delta,
        "note": "分布通道反事实：移除预测片段后重算 CPD（真实统计重算，未重跑语义模型）",
        "latency_ms": round(time.time() * 1000 - now, 1),
    }


def _public_input(sample: dict) -> dict:
    family = sample["family"]
    label = sample["label"]
    text = sample["text"]
    if label == "attack":
        return {
            "disclosure": "redacted",
            "content": _REDACTED_NOTICE,
            "redaction_notice": _REDACTED_NOTICE,
            "intent_summary": _PROTECTED_INTENT.get(family, "对抗性请求识别"),
            "public_note": _PROTECTED_CONTENT.get(family, "对抗性请求。"),
            "chars": len(text),
        }
    intent = text if len(text) <= 60 else text[:57] + "..."
    return {
        "disclosure": "full",
        "content": text,
        "redaction_notice": "",
        "intent_summary": intent,
        "public_note": "公开安全样本（论文公开经典模式）。",
        "chars": len(text),
    }


def run_lab_detection(sample_id: str) -> dict:
    """对单个冻结样本执行真实检测运行，产出对齐 LabRunResult 的结构。"""
    sample = _get_sample(sample_id)
    text = sample["text"]
    family = sample["family"]
    t0 = time.time()

    # lab 结构自带 evidence，不需要写回案件库（LAB-xxx 缓存案件不落盘）
    sem = run_prompt_analysis(text, task_id=f"LAB-{sample_id}", add_evidence=False)
    sem_ms = round((time.time() - t0) * 1000, 1)

    t1 = time.time()
    signals, det_meta = _build_signals(text)
    obs_ms = round((time.time() - t1) * 1000, 1)

    # 直接消费 run_prompt_analysis 的权威融合字段（语义三档 × CPD 分层），与主分析面板口径完全一致
    sem_sev = sem.get("semantic_severity") or "unavailable"
    decision = sem.get("decision") or ("review" if sem_sev in ("unavailable",) else "allow")
    status = sem.get("detector_status")
    cpd_alarm = status == "token_anomaly_candidate"
    # 权威口径：仅 alarm 级候选才进入 suspicious_span；观察级候选不参与处置与定位评分
    span = det_meta["suspicious_span"]
    if cpd_alarm and span is None and sem.get("cpd_anchor") == "semantic_anchored" \
            and det_meta.get("strongest_char") is not None:
        # 语义锚定升级：观察级候选中最强 |z| 点（方向不限）作为异常起点，标注锚定来源
        span = {"token_start": int(det_meta["strongest_idx"]),
                "char_start": int(det_meta["strongest_char"]),
                "anchor": "semantic_anchored"}
    if not cpd_alarm:
        span = None

    risk_score = round(min(1.0, (0.0 if sem_sev == "safe" else 0.45 if sem_sev == "controversial"
                                 else 0.5 if sem_sev == "unavailable" else 0.8)
                           + (0.2 if cpd_alarm else 0.0)), 3)
    detector_score = round(min(1.0, det_meta["max_z"] / 4.0), 3)

    t2 = time.time()
    cf = _counterfactual(text, span["char_start"] if span else None, det_meta["max_z"])
    cf_ms = round((time.time() - t2) * 1000, 1)

    t3 = time.time()
    kb_chunks = []
    try:
        kb_chunks = search_knowledge_struct(_KB_QUERIES.get(family, "提示词注入"), top_k=2, min_score=0.2) or []
    except Exception:
        kb_chunks = []
    kb_ms = round((time.time() - t3) * 1000, 1)

    sem_model = sem.get("semantic_model") or "semantic-guard"
    stages = [
        {"stage_id": "semantic_guard",
         "summary": f"语义检测已完成 · {_SEV_CN.get(sem_sev, sem_sev)} · 模型 {sem_model}",
         "latency_ms": sem_ms},
        {"stage_id": "token_observation",
         "summary": f"Token 观测已完成 · {det_meta['window_size']} 个窗口",
         "latency_ms": obs_ms},
        {"stage_id": "entropy_cpd",
         "summary": (f"CPD 检测完成 · {det_meta['n_candidates']} 个候选（{'CUSUM alarm 级' if sem.get('cpd_anchor') == 'cusum' else '语义锚定 alarm 级'}）· 异常起点 T#{span['token_start']}"
                     if span else
                     (f"CPD 检测完成 · {det_meta['n_candidates']} 个候选（观察级，未触发 alarm）"
                      if det_meta["suspicious_span"] else "CPD 检测完成 · 未发现分布异常候选")),
         "latency_ms": obs_ms},
        {"stage_id": "fixed_fusion",
         "summary": f"融合判定 · 系统动作 {decision} · 风险分 {risk_score} · {sem.get('fusion_reason', '')}",
         "latency_ms": round(sem_ms + obs_ms, 1)},
        {"stage_id": "knowledge_retrieval",
         "summary": (f"知识检索命中 {len(kb_chunks)} 段 · " + "、".join(
             (c.get("title") or c.get("source") or "知识片段") for c in kb_chunks[:2]) if kb_chunks
                     else "知识检索未命中相关知识段落"),
         "latency_ms": kb_ms},
        {"stage_id": "counterfactual",
         "summary": "反事实检查 · " + _CF_CN.get(
             cf.get("interpretation") or cf.get("reason"),
             str(cf.get("reason") or "不适用")),
         "latency_ms": cf.get("latency_ms")},
    ]

    return {
        "run_id": f"lab-{sample_id.lower()}-{int(time.time()*1000)}",
        "sample_id": sample_id,
        "scenario_kind": family,
        "scenario_label": _SCENARIO_LABELS.get(family, family),
        "mode": "frozen",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "public_input": _public_input(sample),
        "stages": stages,
        "detection": {
            "decision": decision,
            "risk_score": risk_score,
            "detector_score": detector_score,
            "detector_status": ("token_anomaly_candidate" if cpd_alarm
                                else "no_token_anomaly"),
            "cpd_anchor": sem.get("cpd_anchor"),
            "semantic_severity": sem_sev,
            "semantic_categories": sem.get("semantic_categories") or [],
            "semantic_latency_ms": sem.get("semantic_latency_ms"),
            "total_latency_ms": round((time.time() - t0) * 1000, 1),
            "fusion_reason": sem.get("fusion_reason") or "",
            "suspicious_span": span,
            "signals": signals,
        },
        "counterfactual": cf,
        "knowledge": {"hits": [
            {"title": (c.get("title") or c.get("source") or "知识片段"),
             "source": c.get("source") or "知识库"}
            for c in kb_chunks
        ]},
        "truth": {
            "label": sample["label"],
            "relation": _TRUTH_RELATION.get(family, "dual_normal"),
            "onset_char": sample.get("onset_char"),
        },
    }
