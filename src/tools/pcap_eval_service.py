"""PCAP 评测中心：对数据集逐文件重放真实检测引擎（_analyze_pcap_file），与 ground truth 对比。

对齐平台评测口径：合成捕获 + 脱敏标签，只报告 precision / recall / F1 / FPR、
Request/Packet 局部定位命中率，以及 rule_only / behavior_only / fused 三种消融结果。
融合指标用于检查链路一致性，不预设融合一定优于单一检测器。
类型映射（检测器 finding type → 数据集标注）：
- port_scan / bruteforce / c2 / sql_injection / dns_tunnel / web_attack / dos_flood / arp_spoof
结果缓存 /tmp/ts_pcap_eval.json；全程只读数据集，不写案件库。
"""
import json
import os
import statistics
import threading
import time

from tools.pcap_tools import _analyze_pcap_file
from tools.pcap_profile import load_ground_truth, DATASET_DIR

CACHE_PATH = os.path.join("/tmp", "ts_pcap_eval.json")
CACHE_VERSION = 3  # 口径版本：v3 = 三消融 + FPR + 局部定位命中率

TYPE_MAP = {
    "port_scan": "port_scan",
    "brute_force": "bruteforce",
    "c2_beacon": "c2",
    "sql_injection": "sql_injection",
    "dns_tunnel": "dns_tunnel",
    "web_attack": "web_attack",
    "dos_flood": "dos_flood",
    "arp_spoof": "arp_spoof",
}

ROUTES = ("rule_only", "behavior_only", "fused")

_state = {"running": False, "progress": 0, "total": 0, "error": None}
_lock = threading.Lock()


def get_state() -> dict:
    return dict(_state)


def _prf(tp: int, fp: int, fn: int, tn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
            "fpr": round(fpr, 3), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _loc_hit(finding: dict, ranges: list) -> bool:
    """局部定位命中：检测定位区间 [first_idx, last_idx] 与 GT 攻击包区间相交。"""
    fi, li = finding.get("first_idx"), finding.get("last_idx")
    if fi is None or li is None:
        return False
    for lo, hi in ranges:
        if fi <= hi and li >= lo:
            return True
    return False


def _route_pred(result: dict, route: str) -> list:
    if route == "rule_only":
        fs = result.get("rule_findings", [])
    elif route == "behavior_only":
        fs = result.get("behavior_findings", [])
    else:
        fs = result.get("findings", [])
    return sorted({TYPE_MAP[f["type"]] for f in fs if f["type"] in TYPE_MAP}), fs


def _execute():
    try:
        items = load_ground_truth()
        if not items:
            _state.update(running=False, error="数据集未生成")
            return
        _state["total"] = len(items)

        rows = []
        for it in items:
            path = os.path.join(DATASET_DIR, it["file"])
            t0 = time.time()
            result = _analyze_pcap_file(path)
            latency = round((time.time() - t0) * 1000, 1)
            ranges = [tuple(r) for r in it.get("attack_packet_ranges", [])]

            if "error" in result:
                rows.append({
                    "file": it["file"], "kind": it["kind"], "gt": it.get("attack_types", []),
                    "parsed": False, "error": result["error"],
                    "pred": {}, "latency_ms": latency,
                })
            else:
                pred_map, fs_map = {}, {}
                for route in ROUTES:
                    pred, fs = _route_pred(result, route)
                    pred_map[route] = pred
                    fs_map[route] = fs
                rows.append({
                    "file": it["file"], "kind": it["kind"], "gt": it.get("attack_types", []),
                    "parsed": True, "packets": result["total_packets"],
                    "attack_ranges": [[int(lo), int(hi)] for lo, hi in ranges],
                    "findings": [{k: f[k] for k in ("type", "confidence", "route", "first_idx", "last_idx") if k in f}
                                 for f in result["findings"]],
                    "fs": {route: [{"type": f["type"], "first_idx": f.get("first_idx"),
                                    "last_idx": f.get("last_idx")} for f in fs_map[route]]
                           for route in ROUTES},
                    "pred": pred_map, "latency_ms": latency,
                })
            _state["progress"] = len(rows)

        # ---- 三消融指标：rule_only / behavior_only / fused ----
        ablation = {}
        for route in ROUTES:
            tp = sum(1 for r in rows if r["kind"] == "attack" and r["pred"].get(route))
            fp = sum(1 for r in rows if r["kind"] == "normal" and r["pred"].get(route))
            fn = sum(1 for r in rows if r["kind"] == "attack" and not r["pred"].get(route))
            tn = sum(1 for r in rows if r["kind"] == "normal" and not r["pred"].get(route))
            binary = _prf(tp, fp, fn, tn)

            per_type = {}
            for atype in ("port_scan", "bruteforce", "c2", "sql_injection",
                          "dns_tunnel", "web_attack", "dos_flood", "arp_spoof"):
                sub = [r for r in rows if atype in r["gt"]]
                hit = sum(1 for r in sub if atype in r["pred"].get(route, []))
                per_type[atype] = {"total": len(sub), "hit": hit,
                                   "recall": round(hit / len(sub), 2) if sub else 0.0}

            ablation[route] = {"binary": binary, "per_type_recall": per_type}

        # ---- 局部定位命中率：攻击文件上，检出 finding 的包级定位区间与 GT 攻击包区间相交的比例 ----
        loc_stats = {route: {"total": 0, "hit": 0} for route in ROUTES}
        for r in rows:
            if not r.get("parsed") or r["kind"] != "attack":
                continue
            ranges = [tuple(x) for x in r.get("attack_ranges", [])]
            for route in ROUTES:
                for f in r.get("fs", {}).get(route, []):
                    loc_stats[route]["total"] += 1
                    if _loc_hit(f, ranges):
                        loc_stats[route]["hit"] += 1
        for route in ROUTES:
            st = loc_stats[route]
            ablation[route]["localization"] = {
                "total": st["total"], "hit": st["hit"],
                "hit_rate": round(st["hit"] / st["total"], 3) if st["total"] else None,
            }

        parsed_rows = [r for r in rows if r["parsed"]]
        lat = [r["latency_ms"] for r in parsed_rows]

        cache = {
            "status": "ok",
            "eval_version": CACHE_VERSION,
            "evaluated_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "dataset_files": len(items),
            "metrics": {
                "ablation": ablation,
                "fused": ablation["fused"]["binary"],   # 兼容旧前端字段
                "per_type_recall": ablation["fused"]["per_type_recall"],
                "parse_success_rate": round(len(parsed_rows) / len(rows), 3) if rows else 0,
                "latency": {
                    "avg_ms": round(statistics.mean(lat), 1) if lat else None,
                    "max_ms": round(max(lat), 1) if lat else None,
                },
            },
            "rows": rows,
        }
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False)
        _state["running"] = False
    except Exception as e:
        import traceback
        _state.update(running=False, error=f"{e} | {traceback.format_exc()[-300:]}"[:300])


def run_async() -> dict:
    with _lock:
        if _state["running"]:
            return {"ok": False, "message": "评测进行中"}
        _state.update(running=True, progress=0, total=0, error=None)
    threading.Thread(target=_execute, daemon=True).start()
    return {"ok": True, "message": "PCAP 评测已启动"}


def get_summary() -> dict:
    if _state["running"]:
        return {"status": "running", "progress": _state["progress"], "total": _state["total"]}
    if not os.path.isfile(CACHE_PATH):
        return {"status": "empty", "state": get_state(),
                "message": "尚未评测，点击开始评测对数据集重放检测引擎"}
    try:
        with open(CACHE_PATH, encoding="utf-8") as f:
            cache = json.load(f)
        if cache.get("eval_version") != CACHE_VERSION:
            return {"status": "empty", "state": get_state(),
                    "message": "评测口径已升级（三消融+FPR+定位命中率），请重新评测"}
        if _state["error"]:
            cache["last_error"] = _state["error"]
        return cache
    except Exception as e:
        return {"status": "error", "message": str(e)[:120]}
