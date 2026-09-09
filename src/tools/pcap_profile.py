"""PCAP 数据集画像：对数据集目录逐文件真实解析（dpkt），输出协议/时长/内容可见性统计。

可见性分类（与 Token 侦探知识库对齐）：
- token_eligible         明文应用层内容可读（HTTP 请求/响应、DNS 域名）→ 可做 token 级分析
- traffic_only           仅流量元数据可见（TLS/SSH 加密或纯 SYN 扫描）→ 只能做行为分析
- insufficient_evidence  包数过少或解析失败 → 证据不足
"""
import json
import os
import time
from collections import Counter

from typing import Any

import dpkt

WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")
DATASET_DIR = os.getenv("TS_PCAP_DATA_DIR", os.path.join(WORKSPACE, "data", "pcap"))
GT_PATH = os.path.join(DATASET_DIR, "_ground_truth.json")
CACHE_PATH = os.path.join("/tmp", "ts_profile_cache.json")

HTTP_PORTS = {80, 8080, 8000, 8888}
PLAINTEXT_APP_PORTS = {53, 21, 23, 25}


def _profile_file(path: str) -> dict:
    packets = 0
    proto = Counter()
    app = Counter()
    plain_bytes = 0
    cipher_bytes = 0
    first_ts = None
    last_ts = None
    parse_errors = 0

    try:
        with open(path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            for ts, buf in reader:
                packets += 1
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP):
                        proto["non_ip"] += 1
                        continue
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        proto["TCP"] += 1
                        tcp_seg: Any = ip.data
                        dport = int(tcp_seg.dport)
                        payload = bytes(tcp_seg.data) if tcp_seg.data else b""
                        if dport in HTTP_PORTS and payload:
                            app["http"] += 1
                            plain_bytes += len(payload)
                        elif dport == 443:
                            app["tls"] += 1
                            cipher_bytes += len(payload)
                        elif dport == 22:
                            app["ssh"] += 1
                            cipher_bytes += len(payload)
                        elif payload:
                            app["other_tcp"] += 1
                            plain_bytes += len(payload)
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        proto["UDP"] += 1
                        udp_seg: Any = ip.data
                        dport = int(udp_seg.dport)
                        payload = bytes(udp_seg.data) if udp_seg.data else b""
                        if dport == 53:
                            app["dns"] += 1
                            plain_bytes += len(payload)
                        elif payload:
                            app["other_udp"] += 1
                            plain_bytes += len(payload)
                    elif isinstance(ip.data, dpkt.icmp.ICMP):
                        proto["ICMP"] += 1
                    else:
                        proto["other_ip"] += 1
                except Exception:
                    parse_errors += 1
    except Exception as e:
        return {"status": "unreadable", "error": str(e)[:120], "packets": 0}

    duration = round(last_ts - first_ts, 2) if first_ts is not None and last_ts is not None else 0.0
    size = os.path.getsize(path)

    if packets < 3 or (packets and parse_errors / packets > 0.5):
        visibility = "insufficient_evidence"
    elif plain_bytes > 0:
        visibility = "token_eligible"
    else:
        visibility = "traffic_only"

    return {
        "status": "ok",
        "packets": packets,
        "size_bytes": size,
        "size_kb": round(size / 1024, 1),
        "duration_sec": duration,
        "proto": dict(proto),
        "app": dict(app),
        "plain_bytes": plain_bytes,
        "cipher_bytes": cipher_bytes,
        "parse_errors": parse_errors,
        "visibility": visibility,
    }


_NAME_RULES = [
    ("tuoku", "拖库"), ("dnslog", "DNSLog 外带"), ("powershell", "PowerShell C2"),
    ("webshell", "WebShell 上传"), ("web_upload", "WebShell 上传"), ("sql", "SQL 注入"),
    ("sqli", "SQL 注入"), ("inject", "注入攻击"), ("scan", "端口扫描"), ("brute", "暴力破解"),
]


def _infer_gt() -> list:
    """扫描数据集目录，从文件名语义推断标签；无法推断的标记 unknown（不冒充标签）。"""
    items = []
    try:
        names = sorted(n for n in os.listdir(DATASET_DIR) if n.lower().endswith(".pcap"))
    except OSError:
        return items
    for name in names:
        low = name.lower()
        kinds, tags = [], []
        for key, label in _NAME_RULES:
            if key in low:
                kinds.append("attack")
                tags.append(label)
        db = "PostgreSQL" if "postgresql" in low else ("MSSQL" if "mssql" in low else "")
        tags = [(db + t if t == "拖库" and db else t) for t in tags]
        if kinds:
            items.append({"file": name, "kind": "attack", "attack_types": sorted(set(tags))})
        else:
            # 哈希导出批次等无语义文件名：不猜测标签
            items.append({"file": name, "kind": "unknown", "attack_types": []})
    return items


def load_ground_truth() -> list:
    if os.path.isfile(GT_PATH):
        try:
            with open(GT_PATH, encoding="utf-8") as f:
                gt = json.load(f).get("items", [])
            names = {n for n in os.listdir(DATASET_DIR) if n.lower().endswith(".pcap")}
            if gt and {it["file"] for it in gt} == names:
                return gt
        except Exception:
            pass
    items = _infer_gt()
    if items:
        try:
            os.makedirs(DATASET_DIR, exist_ok=True)
            with open(GT_PATH, "w", encoding="utf-8") as f:
                json.dump({"version": "auto-inferred", "items": items}, f, ensure_ascii=False)
        except Exception:
            pass
    return items


def profile_all(force: bool = False) -> dict:
    """对数据集全部文件真实解析并画像；结果缓存，force=True 强制重算。"""
    if not force and os.path.isfile(CACHE_PATH):
        try:
            with open(CACHE_PATH, encoding="utf-8") as f:
                cache = json.load(f)
            if cache.get("dataset_files") == len(load_ground_truth()):
                cache["cached"] = True
                return cache
        except Exception:
            pass

    items = load_ground_truth()
    if not items:
        return {"status": "empty", "message": "数据集未生成，请先运行 python src/tools/pcap_dataset.py"}

    rows = []
    for it in items:
        path = os.path.join(DATASET_DIR, it["file"])
        prof = _profile_file(path) if os.path.isfile(path) else {"status": "missing"}
        rows.append({
            "file": it["file"],
            "kind": it["kind"],
            "attack_types": it.get("attack_types", []),
            **{k: v for k, v in prof.items() if k != "status"},
            "parse_status": prof.get("status", "ok"),
        })

    vis_dist = Counter(r.get("visibility", "unknown") for r in rows)
    proto_sum = Counter()
    app_sum = Counter()
    for r in rows:
        proto_sum.update(r.get("proto", {}))
        app_sum.update(r.get("app", {}))

    result = {
        "status": "ok",
        "profiled_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
        "dataset_dir": DATASET_DIR,
        "dataset_files": len(items),
        "summary": {
            "total_packets": sum(r.get("packets", 0) for r in rows),
            "total_size_kb": round(sum(r.get("size_bytes", 0) for r in rows) / 1024, 1),
            "max_duration_sec": max((r.get("duration_sec", 0) for r in rows), default=0),
            "visibility_dist": dict(vis_dist),
            "proto_dist": dict(proto_sum),
            "app_dist": dict(app_sum),
            "attack_files": sum(1 for r in rows if r["kind"] == "attack"),
            "normal_files": sum(1 for r in rows if r["kind"] == "normal"),
            "unknown_files": sum(1 for r in rows if r["kind"] not in ("attack", "normal")),
        },
        "items": rows,
    }
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False)
    except Exception:
        pass
    return result
