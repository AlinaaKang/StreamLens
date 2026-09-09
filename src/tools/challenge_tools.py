"""Token 侦探挑战工具（对齐参考实现 token-detective-challenge）。

- 关卡组：三关速战（SAFE/SHIFT/AD）· 五关完整挑战（+GCG/ADVP）
- 检测：真实三路（语义 Guard + 窗口分布观测 + 融合）+ 知识检索 + 分布反事实（lab_run_service）
- 受保护样本：攻击类样本不展示原文，只给家族级说明与 "[对抗攻击内容已隐藏]"
- 计分：处置 50 / 证据关系 20 / 定位 30（与 CPD 起点的窗口距离 0-3→30、4-8→15、9+→0）；
  无 CPD 候选时定位不适用、不计入满分；按适用分值归一化百分制；总分 = 各轮平均
- 揭晓：玩家研判 vs 系统原始动作 + 检测结果逐阶段回放 + 反事实敏感性
"""
import json
import logging
import os
import random
import threading
import time
from typing import Any

from langchain.tools import tool
from tools.case_store import case_store
from tools.pcap_tools import _analyze_pcap_file
from tools.lab_run_service import (
    _SCENARIO_LABELS,
    _get_sample as _lab_sample,
    _public_input as _lab_public_input,
    build_round_plan,
    run_lab_detection,
)
from tools.entropy_detector import detect_change_points

logger = logging.getLogger("uvicorn.error")

GROUP_LABELS = {"three": "三关速战", "five": "五关完整挑战"}
_GROUP_ROUNDS = {"three": 3, "five": 5}

_SEV_CN = {"safe": "语义安全", "controversial": "语义存疑",
           "unsafe": "语义风险", "unavailable": "语义通道不可用"}
_DEC_CN = {"allow": "放行", "review": "人工复核", "block": "拦截"}
_REL_CN = {"dual_normal": "双证正常", "semantic_only": "仅语义异常",
           "distribution_only": "仅分布异常", "dual_risk": "双证风险"}

WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")

# PCAP 实验神秘流量池（文件名, 真实攻击类型, 攻击源 IP）
PCAP_POOL = [
    ("port_scan.pcap", "port_scan", "10.0.0.66"),
    ("brute_force.pcap", "brute_force", "10.0.0.77"),
    ("c2_beacon.pcap", "c2_beacon", "10.0.0.88"),
    ("data_exfil.pcap", "data_exfil", "10.0.0.99"),
    ("normal_traffic.pcap", "none", ""),
]
ATTACK_TYPE_LABELS = {
    "none": "无攻击（正常流量）", "port_scan": "端口扫描", "brute_force": "暴力破解",
    "c2_beacon": "C2 心跳回连", "data_exfil": "数据外传",
}


def _norm_group(group: str = "", rounds: int = 0) -> str:
    if group in ("three", "five"):
        return group
    return "three" if (rounds or 3) <= 3 else "five"


def _rounds_of(group: str) -> int:
    return _GROUP_ROUNDS.get(group, 3)


def _get_or_create_challenge_case(mode: str = "challenge") -> str:
    """工具链路案件复用：get_current 返回 dict（历史遗留），需取 task_id；
    仅续用"有进行中轮次"的案件，已收官的局 start 时开新局"""
    cur = case_store.get_current(mode)
    cur_id = cur.get("task_id") if isinstance(cur, dict) else cur
    if cur_id:
        data = case_store.get_task(cur_id) or {}
        if data.get("mode") == mode and (data.get("challenge_current") or (
                data.get("challenge_current") is None and not data.get("challenge_history"))):
            return cur_id
    created = case_store.create_task(
        mode, title="Token 侦探挑战", origin="challenge",
        description="冻结样本研判挑战（真实三路检测）")
    case_store.set_current(mode, created)
    return created


def _streak_of(history: list) -> int:
    n = 0
    for h in reversed(history):
        if h.get("norm", 0) >= 100:
            n += 1
        else:
            break
    return n


def _score_avg(history: list) -> int:
    return round(sum(h.get("norm", 0) for h in history) / len(history)) if history else 0


def _relation_from_lab(lab: dict) -> str:
    """语义严重度 × 分布候选 → 证据关系四象限（与参考实现一致的系统侧推导）。"""
    det = lab.get("detection") or {}
    sem_bad = det.get("semantic_severity") in ("controversial", "unsafe")
    dist_bad = det.get("suspicious_span") is not None
    if sem_bad and dist_bad:
        return "dual_risk"
    if sem_bad:
        return "semantic_only"
    if dist_bad:
        return "distribution_only"
    return "dual_normal"


def _prepare_report(task_id: str) -> None:
    """后台预计算当前样本的真实检测运行（lab 结构）。"""
    data = case_store.get_task(task_id) or {}
    cur = data.get("challenge_current")
    if not cur:
        return
    sid = cur.get("sample_id")
    if (data.get("challenge_report") or {}).get("status") == "done":
        return
    case_store.update_task(task_id, challenge_report={"status": "preparing", "sample_id": sid})
    try:
        lab = run_lab_detection(sid)
        # 写回前校验：轮次已推进（current 样本变化）时丢弃迟到结果，防止旧线程覆盖新轮次报告
        latest = (case_store.get_task(task_id) or {}).get("challenge_current") or {}
        if latest.get("sample_id") != sid:
            return
        case_store.update_task(task_id, challenge_report={"status": "done", "lab": lab, "sample_id": sid})
    except Exception as e:
        logger.error("challenge lab prepare failed: %s", e)
        latest = (case_store.get_task(task_id) or {}).get("challenge_current") or {}
        if latest.get("sample_id") == sid:
            case_store.update_task(task_id, challenge_report={"status": "error", "error": str(e)})


def _ensure_report(task_id: str) -> dict:
    data = case_store.get_task(task_id) or {}
    cur = data.get("challenge_current") or {}
    rep = data.get("challenge_report") or {}
    # done 报告与当前轮样本不匹配（迟到线程/清空竞态）视为 STALE，重新预取
    stale = (rep.get("status") == "done" and cur.get("sample_id")
             and rep.get("sample_id") not in (None, cur.get("sample_id")))
    if rep.get("status") not in ("preparing", "done") or stale:
        threading.Thread(target=_prepare_report, args=(task_id,), daemon=True).start()
        rep = {"status": "preparing"}
    return rep


def _wait_report(task_id: str, timeout: float = 120.0) -> dict:
    rep = _ensure_report(task_id)
    t0 = time.time()
    while rep.get("status") == "preparing" and time.time() - t0 < timeout:
        time.sleep(0.4)
        rep = (case_store.get_task(task_id) or {}).get("challenge_report") or {}
    return rep


def challenge_report_view(task_id: str) -> dict:
    """调查回放数据：三侦探逐行回放 + 曲线信号 + 待检输入（不泄露系统动作与答案）。"""
    data = case_store.get_task(task_id) or {}
    rep = data.get("challenge_report") or {}
    status = rep.get("status", "preparing")
    empty = {"status": status, "error": rep.get("error") or "", "public_input": {},
             "stages": [], "desk": {}, "series": {"entropy": [], "nll": [], "cpd": []},
             "signals": [], "suspicious": None, "scenario_label": ""}
    if status != "done":
        return empty
    try:
        lab = rep["lab"]
        det = lab["detection"]
        pub = lab["public_input"]
        signals = det.get("signals") or []
        span = det.get("suspicious_span")
        sev = det.get("semantic_severity", "safe")
        sev_cn = _SEV_CN.get(sev, "未知")
        cats = det.get("semantic_categories") or []
        sem_stage = next((s for s in lab["stages"] if s["stage_id"] == "semantic_guard"), {})
        stage_summary = {s["stage_id"]: s.get("summary", "") for s in lab["stages"]}

        sem_rows = [
            ["检测状态", "语义检测已完成" if sev != "unavailable" else "语义通道不可用（降级）"],
            ["语义级别", sev_cn],
            ["风险类别", "、".join(cats) if cats else "未命中风险类别"],
            ["模型与耗时", f"真实语义模型 · {sem_stage.get('latency_ms', '-')} ms"],
        ]
        n_cand = sum(1 for s in signals if s.get("risk", 0) >= 0.5)
        cpd_rows = [
            ["观测状态", f"Token 观测已完成（{len(signals)} 个窗口）"],
            ["CPD 状态", (f"发现 {n_cand} 个分布异常候选，最早位于窗口 T#{span['token_start']}"
                          if span else "未发现分布异常候选")],
            ["分数 / 阈值", f"{det.get('detector_score', 0)} / 0.5（CPD z 阈值 2.0 归一）"],
            ["异常起点", (f"T#{span['token_start']}（字符 {span['char_start']}）"
                          if span else "不适用")],
            ["证据边界", "分布异常只代表候选信号，不单独证明恶意"],
        ]
        sem_bad = sev in ("controversial", "unsafe")
        dist_bad = span is not None
        chief_rows = [
            ["证据接收", "已收到语义与分布两路公开证据"],
            ["证据关系", ("两路证据结论一致" if sem_bad == dist_bad
                          else "两路证据结论不一致，以提交研判为准")],
            ["展示边界", "提交研判前不展示系统动作"],
            ["汇总状态", "调查证据已汇总，可进入玩家研判"],
        ]
        stages_out = [
            {"stage_id": "semantic", "title": "语义侦探汇报", "ic": "🛡",
             "rows": sem_rows, "summary": stage_summary.get("semantic_guard", "")},
            {"stage_id": "cpd", "title": "曲线侦探汇报", "ic": "📈",
             "rows": cpd_rows, "summary": stage_summary.get("entropy_cpd", "")},
            {"stage_id": "chief", "title": "小队队长汇报", "ic": "🎖",
             "rows": chief_rows, "summary": stage_summary.get("fixed_fusion", "")},
        ]
        def _smooth(pairs, win=4):
            """展示用滑动平均：压制逐 token 锯齿，保留趋势（不改变检测链路）。"""
            vals = [v for _, v in pairs]
            out = []
            for i in range(len(vals)):
                lo = max(0, i - win + 1)
                seg = vals[lo:i + 1]
                out.append(round(sum(seg) / len(seg), 4))
            return [[p, out[i]] for i, (p, _) in enumerate(pairs)]

        # 旗标候选 = 检测器真实候选（detect_change_points 主链路）中达到处置升级门槛（conf>=0.5，
        # 即 CUSUM 报警主候选）的项；观察级候选（conf<=0.45，含每条必有的兜底定位）不高亮，
        # 避免"普通无害样本亮旗标"误导玩家；GCG 等报警样本仍有旗可标。
        try:
            _sample = _lab_sample(lab["sample_id"])
            _dcp = detect_change_points(_sample["text"]) or {}
            _cands = sorted({c["char_index"] for c in (_dcp.get("candidates") or [])
                             if (c.get("confidence") or 0) >= 0.5})[:5]
        except Exception:
            _cands = []
        series = {"entropy": [[s["char"], s["entropy"]] for s in signals],
                  "nll": [[s["char"], s["nll"]] for s in signals],
                  "cpd": [[s["char"], s["cpd"]] for s in signals],
                  "candidates": _cands,
                  "threshold": 2.0, "length": pub.get("chars", 0),
                  "earliest_cpd": span["char_start"] if span else None}
        # desk 头部 CPD 观测文案与真实检测候选一致（旗标高亮集合），不泄露 GT
        desk = {"semantic": sev_cn,
                "cpd": ("发现分布异常候选（曲线已高亮）" if _cands else "未发现分布异常候选")}
        return {"status": "done", "public_input": pub, "stages": stages_out, "desk": desk,
                "series": series, "signals": signals, "suspicious": span,
                "scenario_label": lab.get("scenario_label", "")}
    except Exception as e:
        logger.error("challenge report view failed: %s", e)
        empty["status"] = "error"
        empty["error"] = str(e)
        return empty


def _challenge_start_core(task_id: str, group: str = "", rounds: int = 0,
                          force_new: bool = False) -> dict:
    g = _norm_group(group, rounds)
    total = _rounds_of(g)
    data = case_store.get_task(task_id) or {}
    history = data.get("challenge_history") or []
    order = data.get("challenge_order") or []
    cur = data.get("challenge_current")
    resumed = False
    if (not force_new) and cur and order and len(order) == total and len(history) < len(order):
        round_no = len(history) + 1
        resumed = True
    else:
        try:
            order = build_round_plan(g)
        except ValueError as e:
            case_store.log_action(task_id, "challenge:start_blocked", str(e))
            return {"error": str(e), "round_error": True, "missing_families": True}
        history = []
        round_no = 1
        cur = None
    sample_id = order[round_no - 1]
    sample = _lab_sample(sample_id)
    pub = _lab_public_input(sample)
    case_store.reset_actions(task_id)
    case_store.log_action(task_id, "challenge:start",
                          f"第 {round_no}/{len(order)} 轮 · 样本 {sample_id} · {GROUP_LABELS[g]}")
    case_store.update_task(
        task_id,
        challenge_order=order,
        challenge_history=history,
        challenge_current={"sample_id": sample_id, "round_no": round_no,
                           "total_rounds": len(order), "group": g},
        challenge_report={})
    threading.Thread(target=_prepare_report, args=(task_id,), daemon=True).start()
    return {
        "ok": True, "task_id": task_id,
        "round_no": round_no, "total_rounds": len(order),
        "group": g, "group_label": GROUP_LABELS.get(g, g),
        "sample_id": sample_id,
        "scenario_label": _SCENARIO_LABELS.get(sample["family"], sample["family"]),
        "public_input": pub,
        "badge": ("公开安全样本" if sample["label"] == "benign"
                  else "受保护样本 · 内容已隐藏"),
        "disclosure": pub["disclosure"],
        "chars": pub["chars"],
        "score_avg": _score_avg(history), "streak": _streak_of(history),
        "resumed": resumed, "report_status": "preparing",
    }


def _to_token(onset_token, onset_char, signals: list):
    if onset_token is not None and str(onset_token).strip() != "":
        try:
            t = int(onset_token)
            return None if t < 0 else t
        except (TypeError, ValueError):
            pass
    if onset_char is not None and str(onset_char).strip() != "":
        try:
            c = int(onset_char)
        except (TypeError, ValueError):
            return None
        if c < 0:
            return None
        token = 0
        for s in signals:
            if s.get("char", 0) <= c:
                token = s["index"]
        return token
    return None


def _challenge_answer_core(task_id: str, decision: str = "", relation: str = "",
                           onset_token: Any = None, onset_char: Any = None,
                           auto: bool = False) -> dict:
    data = case_store.get_task(task_id) or {}
    cur = data.get("challenge_current")
    if not cur:
        return {"error": "当前没有进行中的挑战。先使用 action=start 开始一轮。"}
    rep = _wait_report(task_id)
    if rep.get("status") == "error":
        # 对齐权威 round_error：本关检测失败不记录答案与分数，允许重试同一关
        return {"error": f"本关检测运行失败（{rep.get('error') or '未知错误'}），可重试同一关，不记录分数。",
                "round_error": True}
    if rep.get("status") != "done":
        return {"error": f"检测运行未完成（{rep.get('status')}），请稍后重试。", "round_error": True}
    lab = rep["lab"]
    det = lab["detection"]
    signals = det.get("signals") or []
    span = det.get("suspicious_span")

    engine_action = det.get("decision", "review")
    engine_relation = _relation_from_lab(lab)
    engine_onset = span["token_start"] if span else None

    p_action = engine_action if auto else (decision or "").strip()
    p_relation = engine_relation if auto else (relation or "").strip()
    p_token = engine_onset if auto else _to_token(onset_token, onset_char, signals)

    action_ok = p_action == engine_action
    relation_ok = p_relation == engine_relation
    action_score = 50 if action_ok else 0
    relation_score = 20 if relation_ok else 0

    onset_applicable = engine_onset is not None
    onset_score = 0
    onset_dist = None
    if onset_applicable and p_token is not None:
        onset_dist = abs(int(p_token) - int(engine_onset))
        onset_score = 30 if onset_dist <= 3 else 15 if onset_dist <= 8 else 0
    applicable = 70 + (30 if onset_applicable else 0)
    earned = action_score + relation_score + onset_score
    norm = round(100 * earned / applicable) if applicable else 0

    history = data.get("challenge_history") or []
    fam = lab.get("scenario_kind") or ""
    history.append({
        "round_no": len(history) + 1,
        "sample_id": cur["sample_id"], "family": fam,
        "family_label": _SCENARIO_LABELS.get(fam, fam),
        "score": earned, "max": applicable, "norm": norm,
        "scored": earned, "max_score": applicable,
        "auto": bool(auto), "comment": (
            f"动作{'✓' if action_ok else '✗'} 关系{'✓' if relation_ok else '✗'}"
            + ("" if not onset_applicable else f" 定位{'✓' if onset_score == 30 else ('△' if onset_score else '✗')}")),
        "perfect": norm >= 100,
    })
    finished = len(history) >= cur.get("total_rounds", len(history))
    # 轮次推进：完成本轮后自动指向下一轮样本（连续互动，无需重新 start）；完赛则清空
    next_info = None
    if finished:
        new_cur = None
    else:
        order = data.get("challenge_order") or []
        nxt_no = len(history) + 1
        nxt_sid = order[nxt_no - 1] if 0 < nxt_no <= len(order) else cur.get("sample_id")
        new_cur = {"sample_id": nxt_sid, "round_no": nxt_no,
                   "total_rounds": cur.get("total_rounds"), "group": cur.get("group")}
        next_info = {"round_no": nxt_no, "sample_id": nxt_sid, "report_status": "preparing"}
    case_store.log_action(task_id, "challenge:answer",
                          f"第 {cur['round_no']} 轮判分 {norm}（{earned}/{applicable}）")
    # 清空上一轮的检测报告缓存，避免下一轮复用 STALE 报告（_prepare_report 按 current 样本重算）
    case_store.update_task(task_id, challenge_history=history, challenge_current=new_cur,
                           challenge_report=({} if new_cur else (data.get("challenge_report") or {})))
    if new_cur:
        threading.Thread(target=_prepare_report, args=(task_id,), daemon=True).start()

    reveal = {
        "player_action": p_action, "engine_action": engine_action,
        "action_ok": action_ok, "action_score": action_score,
        "player_relation": p_relation, "engine_relation": engine_relation,
        "relation_ok": relation_ok, "relation_score": relation_score,
        "player_onset_token": p_token, "engine_onset_token": engine_onset,
        "onset_applicable": onset_applicable, "onset_dist": onset_dist,
        "onset_score": onset_score,
        "earned": earned, "applicable": applicable, "norm": norm,
        "counterfactual": lab.get("counterfactual"),
        "stages": lab.get("stages") or [],
        "detection": {
            "decision": engine_action, "risk_score": det.get("risk_score"),
            "semantic_severity": det.get("semantic_severity"),
            "semantic_categories": det.get("semantic_categories"),
            "fusion_reason": det.get("fusion_reason"),
            "detector_status": det.get("detector_status"),
            "total_latency_ms": det.get("total_latency_ms"),
        },
        "knowledge": lab.get("knowledge"),
    }
    # 证据链摘要（判分后揭示）：语义侧 + 曲线侧，给前端「证据」行渲染
    _sev = det.get("semantic_severity") or "safe"
    _sev_cn = {"safe": "语义安全", "controversial": "语义存疑", "unsafe": "语义异常"}.get(_sev, _sev)
    _cats = det.get("semantic_categories") or []
    _span = det.get("suspicious_span")
    evidence_brief = [
        {"evidence_id": "semantic", "title": "🛡 语义侦探",
         "text": _sev_cn + (f" · 命中类别：{'、'.join(_cats)}" if _cats else " · 未命中风险类别")},
        {"evidence_id": "cpd", "title": "📈 曲线侦探",
         "text": (f"发现分布异常候选 @ T#{_span['token_start']}" if _span else "未发现分布异常候选")},
        {"evidence_id": "fusion", "title": "🧠 融合结论",
         "text": det.get("fusion_reason") or "—"},
    ]
    return {
        "ok": True, "task_id": task_id,
        "round_no": cur["round_no"], "total_rounds": cur.get("total_rounds"),
        "sample_id": cur["sample_id"],
        "finished": finished, "next": next_info,
        "scenario_label": lab.get("scenario_label"),
        "family_label": lab.get("scenario_label"),
        "scored": earned, "max_score": applicable, "norm": norm,
        "perfect": norm >= 100,
        "streak": _streak_of(history), "score_avg": _score_avg(history),
        "engine": {
            "decision": engine_action, "relation": engine_relation,
            "cpd": bool(onset_applicable), "onset_truth": engine_onset,
            "risk_score": det.get("risk_score"),
        },
        "history": history,
        "finished": finished, "auto": bool(auto),
        "evidence": evidence_brief,
        "items": [
            {"label": "处置动作", "ok": action_ok, "note": f"{_DEC_CN.get(p_action, p_action)} vs 系统 {_DEC_CN.get(engine_action, engine_action)}", "score": action_score},
            {"label": "证据关系", "ok": relation_ok, "note": f"{_REL_CN.get(p_relation, p_relation)} vs 系统 {_REL_CN.get(engine_relation, engine_relation)}", "score": relation_score},
            {"label": "观测起点", "ok": (onset_score == 30) if onset_applicable else None,
             "note": ("不适用（本样本无分布异常候选）" if not onset_applicable
                      else ("未标注起点" if (p_token in (None, -1)) else f"T#{p_token}") + f" vs 系统 T#{engine_onset}（距离 {onset_dist}）"),
             "score": onset_score},
        ],
        "reveal": reveal,
    }


def _format_token_question(task_id: str, cur: dict) -> str:
    data = case_store.get_task(task_id) or {}
    order = data.get("challenge_order") or []
    history = data.get("challenge_history") or []
    sample = _lab_sample(cur["sample_id"])
    pub = _lab_public_input(sample)
    label = _SCENARIO_LABELS.get(sample["family"], sample["family"])
    body = (pub["content"] if pub["disclosure"] == "full"
            else f"{pub['intent_summary']}\n{pub['redaction_notice']}")
    return (
        f"【Token 侦探挑战 · 第 {cur['round_no']}/{len(order)} 轮 · {label}】"
        f"（{GROUP_LABELS.get(cur.get('group', 'three'), '')} · 第 {len(history)} 轮已完成，均分 {_score_avg(history)}）\n"
        f"案件 {task_id} | 样本 {cur['sample_id']} | {pub.get('public_note', '')}\n\n"
        f"待检输入（{pub['disclosure']}）：\n──────────────────────\n{body}\n──────────────────────\n\n"
        f"等侦探小队取证完成后提交三项研判：\n"
        f"1) 处置动作：allow（放行）/ review（人工复核）/ block（拦截）\n"
        f"2) 证据关系：dual_normal / semantic_only / distribution_only / dual_risk\n"
        f"3) 观测起点：曲线窗口序号 T#N（无分布异常填 -1）\n\n"
        f"计分：处置 50 | 证据关系 20 | 定位 30（与 CPD 起点窗口距离 ≤3 得 30、≤8 得 15；"
        f"无 CPD 候选时定位不适用）→ 按适用项归一化百分制\n"
        f"作答：action=answer 提交 decision/relation/onset_token"
    )


@tool
def token_detective_challenge(
    action: str,
    decision: str = "",
    relation: str = "",
    onset_token: Any = None,
    onset_char: Any = None,
    auto: bool = False,
    group: str = "",
) -> str:
    """Token 侦探挑战：冻结样本 + 真实三路检测的研判挑战。

    Args:
        action: start 开始/进入下一轮；answer 提交研判；score 查看战绩
        decision: 处置动作 allow/review/block（answer 时）
        relation: 证据关系 dual_normal/semantic_only/distribution_only/dual_risk（answer 时）
        onset_token: 观测起点窗口序号 T#N，无分布异常填 -1（answer 时）
        onset_char: 兼容旧参数——字符位置起点（answer 时可选）
        auto: 自动演示模式（按系统答案自动复盘）
        group: 关卡组 three（三关速战）/ five（五关完整挑战），start 时可选
    """
    mode = "challenge"
    if action == "start":
        task_id = _get_or_create_challenge_case(mode)
        d = _challenge_start_core(task_id, group=group, force_new=False)
        if d.get("error"):
            return f"开始挑战失败：{d['error']}"
        return _format_token_question(task_id, {
            "sample_id": d["sample_id"], "round_no": d["round_no"],
            "total_rounds": d["total_rounds"], "group": d["group"]})
    if action == "answer":
        task_id = _get_or_create_challenge_case(mode)
        d = _challenge_answer_core(task_id, decision=decision, relation=relation,
                                   onset_token=onset_token, onset_char=onset_char,
                                   auto=auto)
        if d.get("error"):
            return d["error"]
        items = "\n".join(
            f"{'✅' if it['ok'] else '❌' if it['ok'] is not None else '⚪'} {it['label']}：{it['note']}（{it['score']} 分）"
            for it in d["items"])
        rev = d["reveal"]
        cf = rev.get("counterfactual") or {}
        cf_txt = {"risk_reduced": "移除预测片段后分布分数下降，反事实支持该片段贡献异常",
                  "unchanged": "移除预测片段后分布分数未下降，反事实不支持",
                  }.get(cf.get("interpretation"),
                        "本样本无分布候选，反事实不适用")
        det_lines = "\n".join(f"- {s['summary']}（{s['latency_ms']} ms）" for s in (rev.get("stages") or []))
        head = "🤖 自动演示" if d.get("auto") else "🧑‍⚕️ 玩家研判"
        return (
            f"【判分结果】第 {d['round_no']}/{d['total_rounds']} 轮 · {d['scenario_label']} | 样本 {d['sample_id']}\n"
            f"{items}\n"
            f"本轮：{d['scored']}/{d['max_score']} → 归一化 {d['norm']} 分 | 连击 {d['streak']} | 均分 {d['score_avg']}\n\n"
            f"—— 揭晓（{head}）——\n"
            f"系统原始动作：{_DEC_CN.get(rev['engine_action'], rev['engine_action'])}"
            f"（风险分 {rev['detection'].get('risk_score')}）\n"
            f"融合依据：{rev['detection'].get('fusion_reason')}\n\n"
            f"反事实敏感性：{cf_txt}\n\n"
            f"检测结果回放：\n{det_lines}\n\n"
            + (f"🏁 挑战已完成！最终均分 {d['score_avg']} 分（{d['total_rounds']} 轮）。"
               f"使用 action=score 查看完整战绩，或 action=start 开启新一局。"
               if d["finished"] else
               f"下一轮：action=start 抽取下一关样本；action=score 查看累计战绩"))
    if action == "score":
        task_id = _get_or_create_challenge_case(mode)
        data = case_store.get_task(task_id) or {}
        history = data.get("challenge_history") or []
        if not history:
            return "还没有完成的轮次。先使用 action=start 开始一轮。"
        lines = "\n".join(
            f"  - {h.get('sample_id', '?')} ({h.get('family', '?')}): {h.get('norm', 0)} 分 | {h.get('comment', '')}"
            for h in history)
        return (f"【挑战战绩】案件 {task_id}\n{lines}\n"
                f"最终均分：{_score_avg(history)} 分 / 100（{len(history)} 轮）")
    return "无效 action，可选：start / answer / score"


def _pcap_clues(path: str) -> str:
    """从真实流量提取线索（不点破攻击类型）"""
    stats = _analyze_pcap_file(path)
    import dpkt, socket  # 局部引入做画像统计
    proto_cnt, pairs, port_set, src_ports = {}, {}, set(), {}
    sizes, ts_list = [], []
    with open(path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            eth = dpkt.ethernet.Ethernet(buf)
            ip: Any = eth.data
            ts_list.append(ts)
            proto_cnt[ip.p] = proto_cnt.get(ip.p, 0) + 1
            sizes.append(len(buf))
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp: Any = ip.data
                s, d = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                key = f"{s} → {d}:{tcp.dport}"
                pairs[key] = pairs.get(key, 0) + 1
                src_ports.setdefault(s, set()).add(tcp.dport)
    top_pairs = sorted(pairs.items(), key=lambda x: -x[1])[:3]
    dur = (ts_list[-1] - ts_list[0]) if len(ts_list) > 1 else 0
    lines = [
        f"· 数据包总数：{stats['total_packets']} | 捕获时长：{dur:.1f}s | 平均包长：{sum(sizes)//len(sizes)}B",
        f"· 协议分布：{proto_cnt}",
        "· 通信最频繁的会话 Top3：" + "；".join(f"{k}（{v}包）" for k, v in top_pairs),
    ]
    for src, ports in src_ports.items():
        if len(ports) >= 5:
            sample_ports = sorted(ports)[:8]
            lines.append(f"· 值得注意：{src} 的目的端口高度分散（≥{len(ports)} 个不同端口，如 {sample_ports}）")
    return "\n".join(lines)


@tool
def pcap_detective_challenge(action: str, attack_type: str = "", attacker_ip: str = "") -> str:
    """PCAP 侦探挑战：根据真实流量统计线索猜攻击类型与攻击源。action=start 抽取一个神秘流量文件并给出统计线索；action=answer 提交答案（attack_type=none/port_scan/brute_force/c2_beacon/data_exfil, attacker_ip=攻击源IP）。"""
    ctx_task = _get_or_create_challenge_case("challenge")
    data_dir = os.path.join(WORKSPACE, "assets/test_data")

    if action == "start":
        name, truth_type, truth_ip = random.choice(PCAP_POOL)
        path = os.path.join(data_dir, name)
        case_store.update_task(ctx_task, pcap_challenge_current={
            "file": name, "type": truth_type, "ip": truth_ip})
        case_store.reset_actions(ctx_task)
        case_store.log_action(ctx_task, "pcap_detective_challenge", f"抽取神秘流量 {name}")
        clues = _pcap_clues(path)
        return (
            f"【PCAP 侦探挑战】案件 {ctx_task}\n"
            f"一个神秘流量样本已就位（文件名保密）。以下是真实统计线索：\n\n{clues}\n\n"
            "请研判：1) 攻击类型（无攻击/端口扫描/暴力破解/C2心跳回连/数据外传） 2) 攻击源 IP\n"
            "作答方式：pcap_detective_challenge 工具 action=answer，"
            "attack_type=none|port_scan|brute_force|c2_beacon|data_exfil，attacker_ip=攻击源IP"
        )

    if action == "answer":
        current = (case_store.get_task(ctx_task) or {}).get("pcap_challenge_current")
        if not current:
            return "当前没有进行中的 PCAP 挑战。先 action=start。"
        path = os.path.join(data_dir, current["file"])
        engine = _analyze_pcap_file(path)
        engine_types = {f["type"] for f in engine["findings"]}
        scored, detail = 0, []
        if attack_type == current["type"]:
            scored += 60
            detail.append(f"✅ 攻击类型正确：{ATTACK_TYPE_LABELS[current['type']]} +60")
        else:
            detail.append(f"❌ 攻击类型：你答 {ATTACK_TYPE_LABELS.get(attack_type, attack_type or '未答')}，"
                          f"真相 {ATTACK_TYPE_LABELS[current['type']]} +0")
        if current["type"] == "none":
            detail.append("ℹ️ 本样本为正常流量，无攻击源，IP 分不计入")
        elif attacker_ip and attacker_ip == current["ip"]:
            scored += 40
            detail.append(f"✅ 攻击源正确：{current['ip']} +40")
        else:
            detail.append(f"❌ 攻击源：你答 {attacker_ip or '未答'}，真相 {current['ip']} +0")
        lines = [f"【判分结果】{current['file']}", *detail, f"本轮得分：{scored}/100", "",
                 "—— 引擎检测回执（真实规则引擎）——"]
        if engine_types:
            for f_ in engine["findings"]:
                lines.append(f"  {f_['type']} | 置信度 {f_['confidence']} | {f_.get('summary', '')[:70]}")
        else:
            lines.append("  引擎未命中任何规则（与你对『无攻击』的研判互相印证）")
        case_store.log_action(ctx_task, "pcap_detective_challenge", f"{current['file']} 判分：{scored} 分")
        case_store.update_task(ctx_task, pcap_challenge_current=None)
        lines.append("\naction=start 抽取下一个神秘流量")
        return "\n".join(lines)

    return "无效 action，可选：start / answer"
