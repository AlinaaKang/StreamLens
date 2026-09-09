# -*- coding: utf-8 -*-
"""脱敏审计事件存储（安全事件页数据源）

只记录结构化脱敏元数据，绝不落盘：
- 原始 Prompt / 攻击 suffix / Token 文本
- 模型或 Guard 的原始输出
- 私人路径与密钥
"""
import json
import os
import time
import uuid
import hashlib

WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")
EVENTS_PATH = os.path.join(WORKSPACE, "cases", "ts_events.jsonl")
_LEGACY_EVENTS = "/tmp/ts_events.jsonl"
if os.path.exists(_LEGACY_EVENTS) and not os.path.exists(EVENTS_PATH):
    try:
        os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
        import shutil
        shutil.move(_LEGACY_EVENTS, EVENTS_PATH)
    except Exception:
        pass


def record_event(text: str, risk_level, action, cpd_onset, mode, model_version,
                 latency_ms, source: str, tokens=None, task_id=None, cpd_conf=None) -> str:
    """写入一条脱敏审计事件，返回 request_id"""
    ev = {
        "request_id": uuid.uuid4().hex[:12],
        "ts": int(time.time() * 1000),
        "sha256": hashlib.sha256((text or "").encode("utf-8")).hexdigest(),
        "length": len(text or ""),
        "tokens": tokens,
        "risk_level": risk_level or "unknown",
        "action": action or "unknown",
        "cpd_onset": cpd_onset,
        "cpd_conf": cpd_conf,
        "mode": mode or "-",
        "model_version": model_version or "-",
        "latency_ms": round(float(latency_ms), 1) if latency_ms else None,
        "source": source,
        "task_id": task_id,
    }
    os.makedirs(os.path.dirname(EVENTS_PATH), exist_ok=True)
    with open(EVENTS_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return ev["request_id"]


def read_events(limit: int = 80) -> list:
    if not os.path.exists(EVENTS_PATH):
        return []
    out = []
    with open(EVENTS_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return list(reversed(out))[:limit]


def summarize(events: list) -> dict:
    """聚合统计（真实事件计算）"""
    total = len(events)
    high = sum(1 for e in events if e.get("risk_level") == "high")
    medium = sum(1 for e in events if e.get("risk_level") == "medium")
    blocked = sum(1 for e in events if e.get("action") == "拦截")
    review = sum(1 for e in events if e.get("action") == "人工复核")
    lats = [float(e["latency_ms"]) for e in events if e.get("latency_ms")]
    return {
        "total": total,
        "high": high,
        "medium": medium,
        "blocked": blocked,
        "review": review,
        "avg_latency_ms": round(sum(lats) / len(lats), 1) if lats else None,
    }
