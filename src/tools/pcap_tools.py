"""PCAP 数据调查工具集：预检 / 批量检测 / 证据查看 / 攻击链关联

检测引擎（真实解析，非模拟）：
- 端口扫描：单源 -> 同目标大量不同端口 SYN（T1046）
- 暴力破解：认证端口高频重复连接（T1110）
- C2 心跳：等间隔周期性小包通信（T1071）
- 数据外传：单连接大流量上行（T1041/T1048）
- SQL 注入：明文 HTTP 请求中的注入特征（T1190）
- DNS 隧道：超长子域名高频查询隐蔽信道（T1071.004/T1048.003）
- Web 攻击：路径遍历/命令注入/XSS 载荷特征（T1190）
- DoS 洪泛：单源高速 SYN 洪水（T1498）
- ARP 欺骗：同 IP 多 MAC 冲突宣告（T1557.002）
"""
import hashlib
import ipaddress
import logging
import math
import os
import re
import time
from urllib.parse import unquote
from collections import defaultdict
from typing import Any, Optional

import dpkt
from langchain.tools import tool
from coze_coding_utils.log.write_log import request_context
from coze_coding_utils.runtime_ctx.context import new_context

from tools.case_store import case_store, resolve_task_for_session, get_session_key

logger = logging.getLogger(__name__)

WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")
MAX_BATCH_FILES = 20
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# 检测阈值（与知识库 network_pcap.md 对齐）
PORT_SCAN_MIN_PORTS = 20        # 扫描判定：不同目的端口数
BRUTE_FORCE_MIN_CONNS = 50      # 暴力破解判定：同源目对连接数
AUTH_PORTS = {21, 22, 23, 3389, 3306, 5432, 6379}
C2_MIN_OCCURRENCES = 5          # C2 心跳判定：至少通信次数
C2_CV_THRESHOLD = 0.25          # 间隔变异系数上限
C2_MIN_DURATION = 900           # 持续时间下限（秒）：短周期会话多为正常心跳，长会话才值得告警
EXFIL_BYTES_THRESHOLD = 1024 * 1024  # 外传判定：单连接上行 1MB
SQLI_MIN_HITS = 3               # SQL 注入判定：至少命中特征次数
DNS_TUNNEL_MIN_LONG = 20        # DNS 隧道判定：超长子域名查询次数
DNS_LONG_LABEL = 24             # 单个标签长度下限（正常域名标签极少超过 24 字符）
WEB_ATTACK_MIN_HITS = 3         # Web 攻击载荷判定：至少命中特征次数
DOS_MIN_RATE = 200.0            # DoS 洪泛判定：SYN 速率下限（包/秒；须远高于端口扫描的典型速率）
DOS_MIN_PKTS = 100              # DoS 洪泛判定：最少 SYN 包数
ARP_CONFLICT_MACS = 2           # ARP 欺骗判定：同 IP 宣告的不同 MAC 数

# SQL 注入特征（先 URL 解码再匹配，大小写不敏感）
_SQLI_RE = re.compile(
    r"union\s+select|select\s+.{1,120}?\s+from\s+information_schema|"
    r"'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b|"
    r"sleep\s*\(\s*\d+|waitfor\s+delay|benchmark\s*\(",
    re.IGNORECASE,
)

# Web 攻击载荷特征：路径遍历 / 命令注入 / XSS（先 URL 解码再匹配，大小写不敏感）
_WEB_RE = re.compile(
    r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows|win\.ini|"
    r";\s*cat\s+/|;\s*ls\s|;\s*id\b|\|\s*cat\s+/|`cat\s|%\x2fcath|"
    r"<\s*script|javascript:|onerror\s*=|onload\s*=|alert\s*\(",
    re.IGNORECASE,
)


def _resolve_file(file_ref: str) -> tuple[str, str]:
    """解析文件引用：本地路径或 URL，返回 (本地路径, 显示名)"""
    file_ref = file_ref.strip()
    if file_ref.startswith(("http://", "https://")):
        import requests
        ctx = request_context.get() or new_context(method="pcap_download")
        name = file_ref.split("?")[0].rstrip("/").split("/")[-1] or "download.pcap"
        local = os.path.join("/tmp", f"{int(time.time())}_{name}")
        headers = {"User-Agent": "StreamLensAgent/1.0"}
        with requests.get(file_ref, headers=headers, stream=True, timeout=120) as r:
            r.raise_for_status()
            size = 0
            with open(local, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    size += len(chunk)
                    if size > MAX_FILE_SIZE:
                        raise ValueError(f"文件超过大小限制 {MAX_FILE_SIZE // 1024 // 1024}MB")
                    f.write(chunk)
        return local, name
    # 本地路径：支持相对 workspace 的路径
    if not os.path.isabs(file_ref):
        cand = os.path.join(WORKSPACE, file_ref)
        file_ref = cand if os.path.exists(cand) else file_ref
    if not os.path.exists(file_ref):
        raise FileNotFoundError(f"文件不存在: {file_ref}")
    return file_ref, os.path.basename(file_ref)


def _get_task_pcap(new_task: bool = False) -> str:
    """获取或创建当前 PCAP 案件（同一会话绑定同一任务，除非 new_task）"""
    if get_session_key():
        sess_tid = resolve_task_for_session(case_store, "pcap", "PCAP 数据调查")
        if sess_tid:
            return sess_tid
    if new_task:
        task_id = case_store.create_task(mode="pcap", title="PCAP 数据调查")
        case_store.set_current(task_id)
        return task_id
    task = case_store.get_current(mode="pcap")
    if task is None:
        task_id = case_store.create_task(mode="pcap", title="PCAP 数据调查")
        case_store.set_current(task_id)
        return task_id
    case_store.set_current(task["task_id"])
    return task["task_id"]


# ==================== Tools ====================

@tool
def pcap_preflight(file_refs: str, new_task: bool = False) -> str:
    """对 PCAP 文件执行沙箱预检：校验格式、大小、计算哈希并加入当前 PCAP 调查任务。file_refs 为逗号分隔的文件路径或URL列表（单批最多20个）。当用户明确要求"新开案件/重新开始"时传 new_task=true。"""
    try:
        refs = [r.strip() for r in file_refs.split(",") if r.strip()]
        if not refs:
            return "错误：请提供 PCAP 文件路径或 URL（多个用英文逗号分隔）。"
        if len(refs) > MAX_BATCH_FILES:
            return f"错误：单批最多 {MAX_BATCH_FILES} 个文件，当前 {len(refs)} 个。请分批导入。"

        if new_task:
            task_id = case_store.create_task(mode="pcap", title="PCAP 数据调查")
            case_store.set_current(task_id)
        else:
            task_id = _get_task_pcap(new_task=new_task)
        task = case_store.get_task(task_id)
        known_hashes = {f["sha256"] for f in task.get("pcap_files", []) or []}

        lines = [f"【PCAP 预检】任务 {task_id}", ""]
        added, skipped = [], []
        for ref in refs:
            try:
                local, name = _resolve_file(ref)
                size = os.path.getsize(local)
                if size > MAX_FILE_SIZE:
                    lines.append(f"- {name}: 超过大小限制，拒绝导入")
                    continue
                with open(local, "rb") as f:
                    head = f.read(4)
                    f.seek(0)
                    sha = hashlib.sha256(f.read(1024 * 1024)).hexdigest() + ("..." if size > 1024 * 1024 else "")
                # 魔数校验
                if head not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
                    lines.append(f"- {name}: 格式不是标准 PCAP（魔数 {head.hex()}），拒绝导入")
                    continue
                if sha in known_hashes:
                    lines.append(f"- {name}: 重复文件（sha256 命中已导入），幂等跳过")
                    skipped.append(name)
                    continue
                # 统计包数
                pkt_count = 0
                try:
                    with open(local, "rb") as f:
                        reader = dpkt.pcap.Reader(f)
                        for _ in reader:
                            pkt_count += 1
                except Exception as e:
                    logger.warning(f"pkt count failed {name}: {e}")

                file_rec = {"name": name, "local_path": local, "size": size, "sha256": sha, "packet_count": pkt_count, "imported_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00")}
                task = case_store.get_task(task_id)
                task.setdefault("pcap_files", []).append(file_rec)
                case_store.update_task(task_id, pcap_files=task["pcap_files"])
                known_hashes.add(sha)
                added.append(file_rec)
                lines.append(f"- {name}: 校验通过 | {size / 1024:.1f} KB | {pkt_count} packets | sha256={sha[:16]}...")
            except Exception as e:
                lines.append(f"- {ref}: 预检失败 ({e})")

        lines.append("")
        total_files = len(case_store.get_task(task_id).get("pcap_files", []))
        lines.append(f"导入成功 {len(added)} 个 / 幂等跳过 {len(skipped)} 个 | 任务累计 {total_files} 个文件")
        lines.append("下一步建议：调用 pcap_batch_detect 执行批量异常检测。")
        case_store.reset_actions(task_id)
        case_store.log_action(task_id, "pcap_preflight",
                              f"格式校验+导入，任务累计 {len(task.get('pcap_files', []))} 个文件")
        lines.append(case_store.build_chain(
            task_id,
            observe=f"用户提交 {len(refs)} 个 PCAP 文件引用",
            plan="pcap_preflight：格式/大小/哈希预检与脱敏登记",
            close="预检通过≠攻击结论；下一步需 pcap_batch_detect 批量检测",
        ))
        return "\n".join(lines)
    except Exception as e:
        logger.exception("pcap_preflight failed")
        return f"预检失败：{e}"


def _detect_port_scan(syn_flows: dict) -> list:
    """规则路·端口扫描: syn_flows[(src,dst,dport,proto)] = [(ts, pkt_idx)...]，按 (src,dst) 聚合不同端口"""
    by_src_dst = defaultdict(lambda: defaultdict(list))
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto == "TCP":
            by_src_dst[(src, dst)][dport].extend(events)

    findings = []
    for (src, dst), ports in by_src_dst.items():
        if len(ports) >= PORT_SCAN_MIN_PORTS:
            all_events = [ev for evs in ports.values() for ev in evs]
            all_ts = sorted(t for t, _ in all_events)
            all_idx = [i for _, i in all_events]
            duration = all_ts[-1] - all_ts[0] if len(all_ts) > 1 else 0
            ports_sorted = sorted(ports.keys())
            findings.append({
                "type": "port_scan",
                "attacker": src, "target": dst,
                "unique_ports": len(ports),
                "port_range": f"{ports_sorted[0]}-{ports_sorted[-1]}",
                "packet_count": sum(len(v) for v in ports.values()),
                "first_seen": all_ts[0], "last_seen": all_ts[-1], "duration_sec": round(duration, 1),
                "first_idx": min(all_idx), "last_idx": max(all_idx),
                "confidence": round(min(0.92, 0.6 + len(ports) * 0.008), 2),
            })
    return findings


def _detect_brute_force(syn_flows: dict) -> list:
    by_pair = defaultdict(list)
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto == "TCP" and dport in AUTH_PORTS:
            by_pair[(src, dst, dport)].extend(events)

    findings = []
    for (src, dst, dport), events in by_pair.items():
        if len(events) >= BRUTE_FORCE_MIN_CONNS:
            ts_sorted = sorted(t for t, _ in events)
            idxs = [i for _, i in events]
            duration = ts_sorted[-1] - ts_sorted[0] if len(ts_sorted) > 1 else 0
            rate = len(ts_sorted) / duration if duration > 0 else len(ts_sorted)
            findings.append({
                "type": "brute_force",
                "attacker": src, "target": dst, "port": dport,
                "connections": len(ts_sorted),
                "duration_sec": round(duration, 1),
                "rate_per_sec": round(rate, 2),
                "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.9, 0.55 + len(ts_sorted) * 0.004), 2),
            })
    return findings


def _detect_c2_beacon(flows: dict) -> list:
    """规则路·C2 心跳：等间隔周期通信（按方向检测周期性，再按无序主机对去重合并报告）"""
    by_pair = defaultdict(list)
    for (src, dst, dport, proto), events in flows.items():
        if proto == "TCP" and isinstance(events, list) and events:
            by_pair[(src, dst, dport)].extend(events)

    raw_findings = []
    for (src, dst, dport), events in by_pair.items():
        ev_ts = [(t, i) for t, i, _ in events if isinstance(t, (int, float))]
        ts_sorted = sorted(t for t, _ in ev_ts)
        if len(ts_sorted) < C2_MIN_OCCURRENCES:
            continue
        intervals = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        if not intervals:
            continue
        # 主周期取中位数：突发外传/重传等离群间隔不参与周期统计
        srt = sorted(intervals)
        median_iv = srt[len(srt) // 2]
        if median_iv <= 0:
            continue
        regular = [iv for iv in intervals if abs(iv - median_iv) <= median_iv * 0.6]
        if len(regular) < C2_MIN_OCCURRENCES - 1:
            continue
        mean_iv = sum(regular) / len(regular)
        variance = sum((iv - mean_iv) ** 2 for iv in regular) / len(regular)
        cv = math.sqrt(variance) / mean_iv if mean_iv > 0 else 1.0
        duration = ts_sorted[-1] - ts_sorted[0]
        if cv < C2_CV_THRESHOLD and duration >= C2_MIN_DURATION:
            idxs = [i for _, i in ev_ts]
            raw_findings.append({
                "type": "c2_beacon",
                "src": src, "dst": dst, "port": dport,
                "occurrences": len(ts_sorted),
                "mean_interval_sec": round(mean_iv, 2),
                "interval_cv": round(cv, 3),
                "outlier_ratio": round(1 - len(regular) / len(intervals), 2),
                "duration_sec": round(duration, 1),
                "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.85, 0.55 + (C2_CV_THRESHOLD - cv) + len(regular) * 0.005), 2),
            })

    # 按无序主机对去重：同一会话双向命中只保留 occurrences 最多的一条
    dedup = {}
    for f in raw_findings:
        pair = tuple(sorted([f["src"], f["dst"]]))
        if pair not in dedup or f["occurrences"] > dedup[pair]["occurrences"]:
            dedup[pair] = f
    return list(dedup.values())


def _detect_data_exfil(conn_bytes: dict) -> list:
    """规则路·数据外传：单连接上行字节数异常"""
    findings = []
    for (src, dst, dport), info in conn_bytes.items():
        total = info["bytes"]
        if total >= EXFIL_BYTES_THRESHOLD:
            findings.append({
                "type": "data_exfil",
                "src": src, "dst": dst, "port": dport,
                "upload_bytes": total,
                "upload_mb": round(total / 1024 / 1024, 2),
                "first_idx": min(info["idx"]), "last_idx": max(info["idx"]),
                "confidence": round(min(0.85, 0.5 + total / EXFIL_BYTES_THRESHOLD * 0.1), 2),
            })
    return findings


def _detect_sql_injection(sqli_hits: dict) -> list:
    """规则路·SQL 注入检测：明文 HTTP 请求中命中注入特征（T1190 Exploit Public-Facing Application）"""
    findings = []
    for (src, dst, dport), info in sqli_hits.items():
        n = info["hits"]
        if n >= SQLI_MIN_HITS:
            findings.append({
                "type": "sql_injection",
                "attacker": src, "target": dst, "port": dport,
                "hits": n,
                "first_idx": min(info["idx"]), "last_idx": max(info["idx"]),
                "confidence": round(min(0.9, 0.5 + n * 0.01), 2),
            })
    return findings


def _detect_web_attack(web_hits: dict) -> list:
    """规则路·Web 攻击载荷检测：路径遍历/命令注入/XSS 特征命中（T1190）"""
    findings = []
    for (src, dst, dport), info in web_hits.items():
        n = info["hits"]
        if n >= WEB_ATTACK_MIN_HITS:
            findings.append({
                "type": "web_attack",
                "attacker": src, "target": dst, "port": dport,
                "hits": n,
                "kinds": sorted(info["kinds"]),
                "first_idx": min(info["idx"]), "last_idx": max(info["idx"]),
                "confidence": round(min(0.9, 0.5 + n * 0.01), 2),
            })
    return findings


def _detect_dns_tunnel(queries: dict) -> list:
    """规则路·DNS 隧道检测：超长子域名高频查询（隐蔽信道/数据外传，T1071.004/T1048.003）"""
    findings = []
    for (src, dst), info in queries.items():
        if info["long_count"] >= DNS_TUNNEL_MIN_LONG:
            findings.append({
                "type": "dns_tunnel",
                "attacker": src, "target": dst, "port": 53,
                "queries": info["total"],
                "long_label_queries": info["long_count"],
                "unique_domains": len(info["domains"]),
                "sample_domain": info["sample"],
                "first_idx": min(info["long_idx"]), "last_idx": max(info["long_idx"]),
                "confidence": round(min(0.9, 0.5 + info["long_count"] * 0.01), 2),
            })
    return findings


def _detect_dos_flood(syn_flows: dict) -> list:
    """规则路·DoS 洪泛检测：单源目对高速 SYN 洪水（与端口扫描区分：高速率少量端口，T1498）"""
    findings = []
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto != "TCP":
            continue
        if len(events) < DOS_MIN_PKTS:
            continue
        ts_sorted = sorted(t for t, _ in events)
        idxs = [i for _, i in events]
        duration = max(ts_sorted[-1] - ts_sorted[0], 0.001)
        rate = len(ts_sorted) / duration
        if rate >= DOS_MIN_RATE:
            findings.append({
                "type": "dos_flood",
                "attacker": src, "target": dst, "port": dport,
                "syn_packets": len(ts_sorted),
                "duration_sec": round(duration, 2),
                "rate_per_sec": round(rate, 1),
                "first_seen": ts_sorted[0], "last_seen": ts_sorted[-1],
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.92, 0.6 + rate / 1000 * 0.3), 2),
            })
    return findings


def _detect_arp_spoof(arp_map: dict) -> list:
    """规则路·ARP 欺骗检测：同一 IP 被多个不同 MAC 宣告（T1557.002 Adversary-in-the-Middle）"""
    findings = []
    for ip, info in arp_map.items():
        macs = info["macs"]
        if len(macs) >= ARP_CONFLICT_MACS:
            findings.append({
                "type": "arp_spoof",
                "target_ip": ip,
                "mac_count": len(macs),
                "macs": sorted(macs),
                "first_idx": min(info["idx"]), "last_idx": max(info["idx"]),
                "confidence": round(min(0.88, 0.6 + len(macs) * 0.1), 2),
            })
    return findings


def _stats_mean_std(values: list):
    """样本均值/标准差（n-1）；样本不足或零方差返回 None"""
    n = len(values)
    if n < 2:
        return None
    mean = sum(values) / n
    var = sum((v - mean) ** 2 for v in values) / (n - 1)
    std = math.sqrt(var)
    return (mean, std) if std > 0 else None


# ---------------- behavior 检测路：流量行为统计 z-score 判定 ----------------
# 与规则路的差异：不做固定载荷特征/固定绝对阈值判定，而是把每个行为指标放到
# 本文件流量分布中度量其统计异常程度（z-score），阈值语义与规则路独立，
# 用于 rule_only / behavior_only / fused 三路消融评测。

BEHAVIOR_Z = 2.0          # 行为异常 z-score 门槛（相对本文件分布）
BEHAVIOR_Z_STRICT = 2.5   # 高方差指标（如请求长度）用更严门槛


def _behavior_port_scan(syn_flows: dict) -> list:
    """行为路·端口广度：源目对接触端口数的分布异常（z-score）或端口接触速率异常（ports/min）"""
    by_src_dst = defaultdict(lambda: defaultdict(list))
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto == "TCP":
            by_src_dst[(src, dst)][dport].extend(events)
    pairs = [(sd, len(ports)) for sd, ports in by_src_dst.items() if ports]
    st = _stats_mean_std([n for _, n in pairs])
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst), n in pairs:
        if n < 6:
            continue
        evs = [ev for evs in by_src_dst[(src, dst)].values() for ev in evs]
        ts_all = sorted(t for t, _ in evs)
        dur = max(ts_all[-1] - ts_all[0], 0.001)
        ppm = n / dur * 60.0
        z = (n - mean) / std if std > 0 else 0.0
        if z >= BEHAVIOR_Z or ppm >= 30:
            idxs = [i for _, i in evs]
            findings.append({
                "type": "port_scan",
                "attacker": src, "target": dst,
                "unique_ports": n,
                "z_score": round(z, 2),
                "ports_per_min": round(ppm, 1),
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.8, 0.4 + max(z, ppm / 100) * 0.06), 2),
            })
    return findings


def _behavior_brute_force(syn_flows: dict) -> list:
    """行为路·认证频次：认证端口连接尝试的分布异常（z-score）或持续高频（rate/s）"""
    by_pair = defaultdict(list)
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto == "TCP" and dport in AUTH_PORTS:
            by_pair[(src, dst, dport)].extend(events)
    pairs = [(k, ev) for k, ev in by_pair.items() if ev]
    st = _stats_mean_std([len(ev) for _, ev in pairs])
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst, dport), evs in pairs:
        n = len(evs)
        if n < 15:
            continue
        ts_all = sorted(t for t, _ in evs)
        dur = max(ts_all[-1] - ts_all[0], 0.001)
        rate = n / dur
        z = (n - mean) / std if std > 0 else 0.0
        if z >= BEHAVIOR_Z or rate >= 2.0:
            idxs = [i for _, i in evs]
            findings.append({
                "type": "brute_force",
                "attacker": src, "target": dst, "port": dport,
                "connections": n,
                "z_score": round(z, 2),
                "rate_per_sec": round(rate, 1),
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.8, 0.4 + max(z, rate / 10) * 0.06), 2),
            })
    return findings


def _behavior_c2_beacon(flows: dict) -> list:
    """行为路·周期性：间隔变异系数显著低于本文件通信对的普遍水平"""
    pair_events = defaultdict(list)
    for (src, dst, dport, proto), events in flows.items():
        if proto == "TCP" and events:
            pair_events[(src, dst, dport)].extend(events)

    cvs = []
    pair_stats = {}
    for key, events in pair_events.items():
        evs = [(t, i) for t, i, _ in events if isinstance(t, (int, float))]
        plens = sorted(pl for _, _, pl in events if pl > 0)
        # 稳健化：剔除离群大包（如同信道突发外传）后再评估信标体长度均匀性
        if plens:
            med = plens[len(plens) // 2]
            plens = [x for x in plens if x <= max(3 * med, 64)] if med > 0 else plens
        pl_n = len(plens)
        # 信标体长度均匀性：固定长度周期上报是常见 C2 特征，长度随机的心跳多为正常应用
        pl_cv = 0.0
        if len(plens) >= 2:
            pm = sum(plens) / len(plens)
            pl_cv = (sum((x - pm) ** 2 for x in plens) / len(plens)) ** 0.5 / pm if pm > 0 else 1.0
        ts_sorted = sorted(t for t, _ in evs)
        if len(ts_sorted) < 4:
            continue
        intervals = [ts_sorted[i + 1] - ts_sorted[i] for i in range(len(ts_sorted) - 1)]
        mean_iv = sum(intervals) / len(intervals)
        if mean_iv <= 0:
            continue
        var = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        cv = math.sqrt(var) / mean_iv
        cvs.append(cv)
        pair_stats[key] = {"cv": cv, "occ": len(ts_sorted),
                           "dur": ts_sorted[-1] - ts_sorted[0], "idx": [i for _, i in evs],
                           "pl_ratio": pl_n / len(ts_sorted) if ts_sorted else 0,
                           "pl_cv": pl_cv}
    st = _stats_mean_std(cvs) if len(cvs) >= 2 else None
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst, dport), s in pair_stats.items():
        z = (mean - s["cv"]) / std if std and std > 0 else 0  # cv 越低于均值越异常
        if (z >= BEHAVIOR_Z or s["cv"] < 0.45) and s["occ"] >= 6 and s["dur"] >= 300 and s["pl_ratio"] >= 0.5 and s["pl_cv"] <= 0.15:
            findings.append({
                "type": "c2_beacon",
                "src": src, "dst": dst, "port": dport,
                "occurrences": s["occ"],
                "interval_cv": round(s["cv"], 3),
                "payload_ratio": round(s["pl_ratio"], 2),
                "payload_len_cv": round(s["pl_cv"], 2),
                "z_score": round(z, 2),
                "first_idx": min(s["idx"]), "last_idx": max(s["idx"]),
                "confidence": round(min(0.8, 0.4 + max(z, (0.45 - s["cv"]) * 2) * 0.06), 2),
            })
    return findings


def _behavior_data_exfil(conn_bytes: dict) -> list:
    """行为路·外传：上行字节量的分布异常（z-score）或持续高上行速率（KB/s）"""
    conns = [(k, v) for k, v in conn_bytes.items() if v["bytes"] > 0 and len(v["ts"]) >= 2]
    st = _stats_mean_std([v["bytes"] for _, v in conns])
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst, dport), v in conns:
        total = v["bytes"]
        if total < 256 * 1024:
            continue
        dur = max(v["ts"][-1] - v["ts"][0], 0.001)
        rate_kbps = total / 1024.0 / dur
        z = (total - mean) / std if std > 0 else 0.0
        if z >= BEHAVIOR_Z or rate_kbps >= 25:
            findings.append({
                "type": "data_exfil",
                "src": src, "dst": dst, "port": dport,
                "upload_bytes": total,
                "upload_mb": round(total / 1024 / 1024, 2),
                "upload_rate_kbps": round(rate_kbps, 1),
                "z_score": round(z, 2),
                "first_idx": min(v["idx"]), "last_idx": max(v["idx"]),
                "confidence": round(min(0.8, 0.4 + max(z, rate_kbps / 100) * 0.06), 2),
            })
    return findings


def _behavior_dns_tunnel(queries: dict) -> list:
    """行为路·DNS：长标签查询数在本文件查询对分布中的统计异常"""
    pairs = [(k, v) for k, v in queries.items() if v["total"] > 0]
    st = _stats_mean_std([v["long_count"] for _, v in pairs])
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst), info in pairs:
        lc = info["long_count"]
        ratio = lc / info["total"] if info["total"] else 0
        z = (lc - mean) / std if std > 0 else 0.0
        if lc >= 5 and (z >= BEHAVIOR_Z or ratio >= 0.4):
            findings.append({
                "type": "dns_tunnel",
                "attacker": src, "target": dst, "port": 53,
                "queries": info["total"],
                "long_label_queries": lc,
                "long_ratio": round(ratio, 2),
                "z_score": round(z, 2),
                "first_idx": min(info["long_idx"]), "last_idx": max(info["long_idx"]),
                "confidence": round(min(0.8, 0.4 + max(z, ratio * 2) * 0.06), 2),
            })
    return findings


def _behavior_dos_flood(syn_flows: dict) -> list:
    """行为路·洪泛：SYN 速率在本文件源目对分布中的统计异常"""
    pairs = []
    for (src, dst, dport, proto), events in syn_flows.items():
        if proto != "TCP" or len(events) < 2:
            continue
        ts_sorted = sorted(t for t, _ in events)
        dur = max(ts_sorted[-1] - ts_sorted[0], 0.001)
        pairs.append(((src, dst, dport), len(events) / dur, [i for _, i in events]))
    st = _stats_mean_std([r for _, r, _ in pairs])
    mean, std = st if st else (0.0, 0.0)
    findings = []
    for (src, dst, dport), rate, idxs in pairs:
        z = (rate - mean) / std if std > 0 else 0.0
        if z >= BEHAVIOR_Z or rate >= 120:
            findings.append({
                "type": "dos_flood",
                "attacker": src, "target": dst, "port": dport,
                "rate_per_sec": round(rate, 1),
                "z_score": round(z, 2),
                "first_idx": min(idxs), "last_idx": max(idxs),
                "confidence": round(min(0.8, 0.4 + max(z, rate / 200) * 0.06), 2),
            })
    return findings


def _behavior_http_anomaly(http_stats: dict) -> list:
    """行为路·HTTP 请求行为异常：请求频次/平均载荷长度在本文件分布中的统计异常。
    高频重复请求归因 sql_injection（拖库拉取模式），异常长请求归因 web_attack（注入/遍历载荷）。"""
    if not http_stats:
        return []
    counts = [(k, len(v["req_idx"])) for k, v in http_stats.items()]
    lens = [(k, (sum(v["lens"]) / len(v["lens"])) if v["lens"] else 0) for k, v in http_stats.items()]
    st_c = _stats_mean_std([n for _, n in counts])
    st_l = _stats_mean_std([l for _, l in lens])
    findings = []
    flood_keys = set()
    for (src, dst, dport), n in counts:
        z = (n - st_c[0]) / st_c[1] if st_c else 0.0
        if (z >= BEHAVIOR_Z and n >= 8) or n >= 15:
            s = http_stats[(src, dst, dport)]
            flood_keys.add((src, dst, dport))
            findings.append({
                "type": "sql_injection",
                "attacker": src, "target": dst, "port": dport,
                "requests": n,
                "z_score": round(z, 2),
                "behavior_evidence": "request_flood",
                "first_idx": min(s["req_idx"]), "last_idx": max(s["req_idx"]),
                "confidence": round(min(0.75, 0.35 + max(z, n / 15) * 0.06), 2),
            })
    for (src, dst, dport), avg in lens:
        if (src, dst, dport) in flood_keys:
            continue  # 同一连接已有高频归因，避免双计
        z = (avg - st_l[0]) / st_l[1] if st_l else 0.0
        if (z >= BEHAVIOR_Z_STRICT and avg >= 200) or avg >= 150:
            s = http_stats[(src, dst, dport)]
            findings.append({
                "type": "web_attack",
                "attacker": src, "target": dst, "port": dport,
                "avg_request_len": round(avg, 1),
                "z_score": round(z, 2),
                "behavior_evidence": "oversized_requests",
                "first_idx": min(s["req_idx"]), "last_idx": max(s["req_idx"]),
                "confidence": round(min(0.75, 0.35 + max(z, avg / 300) * 0.06), 2),
            })
    return findings


def _behavior_arp_spoof(arp_map: dict) -> list:
    """行为路·ARP：IP-MAC 映射不稳定属于行为层异常（与规则路同语义、独立结构实现）"""
    findings = []
    for ip, info in arp_map.items():
        if len(info["macs"]) >= 2:
            findings.append({
                "type": "arp_spoof",
                "target_ip": ip,
                "mac_count": len(info["macs"]),
                "macs": sorted(info["macs"]),
                "behavior_evidence": "ip_mac_instability",
                "first_idx": min(info["idx"]), "last_idx": max(info["idx"]),
                "confidence": 0.62,
            })
    return findings


def _finding_key(f: dict):
    """融合去重键：同类发现按通信双方归并"""
    t = f["type"]
    if t == "arp_spoof":
        return (t, f.get("target_ip"))
    if t in ("port_scan", "dns_tunnel"):
        return (t, f.get("attacker"), f.get("target"))
    if t in ("brute_force", "dos_flood"):
        return (t, f.get("attacker"), f.get("target"), f.get("port"))
    return (t, f.get("src") or f.get("attacker"), f.get("dst") or f.get("target"), f.get("port"))


def _fuse_findings(rule_f: list, behavior_f: list) -> list:
    """融合路：同类同主体的规则/行为发现归并为一条（confidence 取最大，定位区间取并集）。
    融合只做证据归并，不预设融合优于单路——优劣由三路消融评测如实呈现。"""
    merged: dict = {}
    for f in rule_f:
        g = dict(f)
        g["route"] = "rule"
        merged[_finding_key(g)] = g
    for f in behavior_f:
        k = _finding_key(f)
        if k in merged:
            m = merged[k]
            m["route"] = "both"
            m["confidence"] = max(m["confidence"], f["confidence"])
            m["first_idx"] = min(m["first_idx"], f["first_idx"])
            m["last_idx"] = max(m["last_idx"], f["last_idx"])
            beh_extra = {kk: v for kk, v in f.items()
                         if kk not in ("type", "route", "confidence", "first_idx", "last_idx", "macs")}
            m["behavior_evidence"] = beh_extra
        else:
            g = dict(f)
            g["route"] = "behavior"
            merged[k] = g

    # 归因裁决：同一通信主体上，规则路（载荷/内容证据）与行为路（统计证据）类型冲突时，
    # 行为发现并入规则路的类型——载荷特征对攻击类别的判别力强于行为统计
    rule_by_host = {}
    for k, m in merged.items():
        if m["route"] in ("rule", "both"):
            hosts = tuple(sorted(str(x) for x in k[1:] if x is not None))
            rule_by_host.setdefault(hosts, k)
    for k in list(merged.keys()):
        g = merged[k]
        if g["route"] != "behavior":
            continue
        hosts = tuple(sorted(str(x) for x in k[1:] if x is not None))
        rk = rule_by_host.get(hosts)
        if rk and rk != k:
            m = merged[rk]
            m["route"] = "both"
            m["confidence"] = max(m["confidence"], g["confidence"])
            m["first_idx"] = min(m["first_idx"], g["first_idx"])
            m["last_idx"] = max(m["last_idx"], g["last_idx"])
            beh_extra = {kk: v for kk, v in g.items()
                         if kk not in ("type", "route", "confidence", "first_idx", "last_idx")}
            m["behavior_evidence"] = beh_extra
            del merged[k]
    return list(merged.values())


def _analyze_pcap_file(path: str) -> dict:
    """解析单个 PCAP 文件并运行三路检测。

    检测原理（对齐 PCAP 检测契约）：
    - rule 路：固定阈值/载荷特征规则
    - behavior 路：流量行为统计 z-score（相对本文件分布的异常度）
    - fused 路：同类同主体发现归并（route 标注 rule/behavior/both），不预设融合优于单路
    每条发现附带包索引区间（first_idx/last_idx），供评测计算局部定位命中率。
    文件名/路径不参与任何检测判定或标签。
    """
    flows = defaultdict(list)       # (src,dst,dport,proto) -> [(ts, pkt_idx, payload_len)] 全部流量（C2/行为路用）
    syn_flows = defaultdict(list)   # 仅纯SYN连接尝试（扫描/暴破/洪泛用，避免回包污染）
    conn_bytes = defaultdict(lambda: {"bytes": 0, "idx": [], "ts": []})  # (src,dst,dport) -> uplink bytes + 包索引/时间
    sqli_hits = defaultdict(lambda: {"hits": 0, "idx": []})     # 注入特征命中
    web_hits = defaultdict(lambda: {"hits": 0, "kinds": set(), "idx": []})  # Web攻击特征命中
    dns_queries = defaultdict(lambda: {"total": 0, "long_count": 0, "domains": set(), "sample": "", "long_idx": []})
    http_stats = defaultdict(lambda: {"req_idx": [], "lens": []})  # 明文 HTTP 请求行为
    arp_map = defaultdict(lambda: {"macs": set(), "idx": []})   # ip -> {mac}（ARP 宣告）
    total_packets = 0
    parse_errors = 0
    internal_nets = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"), ipaddress.ip_network("192.168.0.0/16")]

    def is_internal(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return any(a in n for n in internal_nets)
        except ValueError:
            return False

    try:
        with open(path, "rb") as f:
            reader = dpkt.pcap.Reader(f)
            for pkt_idx, (ts, buf) in enumerate(reader):
                total_packets += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    # ARP 层：IP-MAC 宣告冲突（arp_spoof）
                    if isinstance(eth.data, dpkt.arp.ARP):
                        arp = eth.data
                        op = getattr(arp, "op", 0)  # type: ignore[union-attr]
                        spa = getattr(arp, "spa", b"")  # type: ignore[union-attr]
                        sha = getattr(arp, "sha", b"")  # type: ignore[union-attr]
                        if op in (dpkt.arp.ARP_OP_REPLY, dpkt.arp.ARP_OP_REQUEST) and spa:
                            sender_ip = socket_inet_to_str(spa)
                            if sha and not sha.startswith(b"\x00\x00"):
                                entry = arp_map[sender_ip]
                                entry["macs"].add(sha.hex())
                                entry["idx"].append(pkt_idx)
                        continue
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip: Any = eth.data
                    src = socket_inet_to_str(ip.src)
                    dst = socket_inet_to_str(ip.dst)
                    # UDP/DNS 层：子域名长度统计（dns_tunnel）
                    if isinstance(ip.data, dpkt.udp.UDP):
                        udp: Any = ip.data
                        if udp.dport == 53 and udp.data:
                            try:
                                dns = dpkt.dns.DNS(udp.data)
                                if dns.qd and dns.qd[0].name:
                                    name = str(dns.qd[0].name)
                                    key = (src, dst)
                                    q = dns_queries[key]
                                    q["total"] += 1
                                    q["domains"].add(name)
                                    if not q["sample"]:
                                        q["sample"] = name
                                    labels = name.split(".")
                                    if any(len(l) >= DNS_LONG_LABEL for l in labels[:-1] or labels):
                                        q["long_count"] += 1
                                        q["long_idx"].append(pkt_idx)
                            except Exception:
                                pass
                        continue
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp: Any = ip.data
                    payload_len = len(tcp.data) if tcp.data else 0
                    # 仅纯 SYN（无ACK）视为连接尝试 → 扫描/暴破/洪泛检测专用，避免服务端 SYN|ACK 回包造成误报
                    if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):
                        flows[(src, dst, tcp.dport, "TCP")].append((ts, pkt_idx, payload_len))
                        syn_flows[(src, dst, tcp.dport, "TCP")].append((ts, pkt_idx))
                    elif payload_len > 0:
                        flows[(src, dst, tcp.dport, "TCP")].append((ts, pkt_idx, payload_len))
                        cb = conn_bytes[(src, dst, tcp.dport)]
                        cb["bytes"] += payload_len
                        cb["idx"].append(pkt_idx)
                        cb["ts"].append(ts)
                        # 明文 HTTP 请求内容扫描（URL 解码后正则匹配）+ 请求行为统计
                        head = tcp.data[:64]
                        if head.startswith((b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ")):
                            hs = http_stats[(src, dst, tcp.dport)]
                            hs["req_idx"].append(pkt_idx)
                            hs["lens"].append(payload_len)
                            decoded = unquote(tcp.data[:4096].decode("latin-1", errors="ignore"))
                            if _SQLI_RE.search(decoded):
                                sh = sqli_hits[(src, dst, tcp.dport)]
                                sh["hits"] += 1
                                sh["idx"].append(pkt_idx)
                            kinds = {m.group(0).lower() for m in _WEB_RE.finditer(decoded)}
                            if kinds:
                                wh = web_hits[(src, dst, tcp.dport)]
                                wh["hits"] += 1
                                wh["kinds"] |= kinds
                                wh["idx"].append(pkt_idx)
                except Exception:
                    parse_errors += 1
    except Exception as e:
        return {"error": f"解析失败: {e}", "total_packets": 0,
                "rule_findings": [], "behavior_findings": [], "findings": []}

    # ---- 三路检测：rule（规则阈值/特征）+ behavior（行为统计 z-score）+ fused（归并） ----
    rule_findings = []
    rule_findings += _detect_port_scan(syn_flows)
    rule_findings += _detect_brute_force(syn_flows)
    rule_findings += _detect_c2_beacon(flows)
    rule_findings += _detect_data_exfil(conn_bytes)
    rule_findings += _detect_sql_injection(sqli_hits)
    rule_findings += _detect_web_attack(web_hits)
    rule_findings += _detect_dns_tunnel(dns_queries)
    rule_findings += _detect_dos_flood(syn_flows)
    rule_findings += _detect_arp_spoof(arp_map)

    behavior_findings = []
    behavior_findings += _behavior_port_scan(syn_flows)
    behavior_findings += _behavior_brute_force(syn_flows)
    behavior_findings += _behavior_c2_beacon(flows)
    behavior_findings += _behavior_data_exfil(conn_bytes)
    behavior_findings += _behavior_dns_tunnel(dns_queries)
    behavior_findings += _behavior_dos_flood(syn_flows)
    behavior_findings += _behavior_http_anomaly(http_stats)
    behavior_findings += _behavior_arp_spoof(arp_map)

    fused_findings = _fuse_findings(rule_findings, behavior_findings)

    return {
        "total_packets": total_packets,
        "parse_errors": parse_errors,
        "rule_findings": rule_findings,
        "behavior_findings": behavior_findings,
        "findings": fused_findings,
        "internal_ips": sorted({k[0] for k in list(flows) + list(conn_bytes) if is_internal(k[0])}),
        "external_ips": sorted({k[1] for k in list(flows) + list(conn_bytes) if not is_internal(k[1])}),
    }


def socket_inet_to_str(b: bytes) -> str:
    return ".".join(str(x) for x in b)


_ATTACK_META = {
    "port_scan": {"name": "端口扫描", "attack": "疑似网络服务扫描", "mitre": "T1046 Network Service Scanning"},
    "brute_force": {"name": "暴力破解", "attack": "疑似认证暴力破解", "mitre": "T1110 Brute Force"},
    "c2_beacon": {"name": "C2 心跳", "attack": "疑似命令控制(C2)通信", "mitre": "T1071 Application Layer Protocol"},
    "data_exfil": {"name": "数据外传", "attack": "疑似数据外泄", "mitre": "T1041/T1048 Exfiltration"},
    "sql_injection": {"name": "SQL 注入", "attack": "疑似 SQL 注入攻击", "mitre": "T1190 Exploit Public-Facing Application"},
    "web_attack": {"name": "Web 攻击载荷", "attack": "疑似路径遍历/命令注入/XSS 攻击", "mitre": "T1190 Exploit Public-Facing Application"},
    "dns_tunnel": {"name": "DNS 隧道", "attack": "疑似 DNS 隐蔽信道外传", "mitre": "T1071.004 DNS"},
    "dos_flood": {"name": "DoS 洪泛", "attack": "疑似拒绝服务洪泛", "mitre": "T1498 Network Denial of Service"},
    "arp_spoof": {"name": "ARP 欺骗", "attack": "疑似 ARP 中间人欺骗", "mitre": "T1557.002 Adversary-in-the-Middle"},
}


@tool
def pcap_batch_detect() -> str:
    """对当前 PCAP 调查任务中的所有已导入文件执行批量异常检测，输出异常 Packet/流量证据（含协议、方向、时间区间、置信度）。预检通过后必须调用本工具。"""
    try:
        task = case_store.get_current(mode="pcap")
        if task is None or not task.get("pcap_files"):
            return "错误：当前没有已导入的 PCAP 文件。请先调用 pcap_preflight 导入文件。"

        task_id = task["task_id"]
        files = task["pcap_files"]
        lines = [f"【批量检测】任务 {task_id} | 文件数 {len(files)}", ""]

        total_anomalies = 0
        total_failed = 0
        _batch_types = []  # 本批实时统计（task 快照不含本轮新入库证据，禁止用快照统计）
        for f in files:
            path = f["local_path"]
            if not os.path.exists(path):
                total_failed += 1
                lines.append(f"◆ {f['name']}: 本地文件已失效，无法检测（需重新导入）")
                continue
            result = _analyze_pcap_file(path)
            if result.get("error"):
                total_failed += 1
                lines.append(f"◆ {f['name']}: {result['error']}")
                continue

            file_anomalies = len(result["findings"])
            total_anomalies += file_anomalies
            status = "发现异常" if file_anomalies else "未发现异常"
            lines.append(f"◆ {f['name']}: {result['total_packets']} packets | {status}（{file_anomalies} 项）")

            for finding in result["findings"]:
                _batch_types.append(finding["type"])
                meta = _ATTACK_META[finding["type"]]
                try:
                    _summary_txt = _finding_summary(finding)
                except Exception:
                    _summary_txt = str(finding)[:200]
                    logger.warning("finding summary fallback: %s", finding.get("type"))
                try:
                    loc_desc = _loc_desc(finding)
                except Exception:
                    loc_desc = f"pkt {finding.get('first_idx', '?')}-{finding.get('last_idx', '?')}"
                ev = {
                    "source": "pcap_batch_detect",
                    "status": "real",
                    "file": f["name"],
                    "summary": f"{meta['attack']}：{_finding_summary(finding)}",
                    "location": loc_desc,
                    "finding": finding,
                    "supports": [meta["attack"]],
                    "confidence": finding["confidence"],
                    "mitre": meta["mitre"],
                    "limitations": ["仅有流量元数据，无终端进程/身份日志，不能确认攻击成功", "加密流量无法读取载荷，基于连接模式判断"],
                }
                eid = case_store.add_evidence(task_id, ev)
                lines.append(f"  - [{eid}] {meta['attack']} ({meta['mitre']})")
                lines.append(f"    {_summary_txt}")
                lines.append(f"    置信度: {finding['confidence']} | 位置: {loc_desc}")

            if not result["findings"]:
                lines.append("  - 未命中任何检测规则（扫描/爆破/C2/外传/SQL注入/DNS隧道/Web载荷/洪泛/ARP欺骗）")

        lines.append("")
        lines.append(f"【批次汇总】文件 {len(files)} | 异常项 {total_anomalies} | 失败 {total_failed}")
        lines.append("【检测范围】三路检测（规则路：固定阈值与载荷特征；行为路：流量统计分布异常；融合路：证据归并与归因裁决），覆盖八类网络攻击候选：端口扫描、SSH暴力破解、C2心跳、数据外传、SQL注入、DNS隧道、Web攻击载荷、SYN洪泛、ARP欺骗；"
                     "已知局限：0day漏洞利用、加密流量内容解密、APT渗透链不在规则覆盖内")
        # 审计事件：仅记录检测动作（一般对话不产生安全事件）；统计用本批实时 findings，与报告正文口径一致
        try:
            _sev_map = {"c2_beacon": "high", "data_exfil": "high", "brute_force": "medium", "port_scan": "medium",
                        "sql_injection": "high", "web_attack": "high", "dns_tunnel": "high",
                        "dos_flood": "high", "arp_spoof": "medium"}
            _type_cnt = {}
            _worst = "none"
            for _t in _batch_types:
                _type_cnt[_t] = _type_cnt.get(_t, 0) + 1
                if _sev_map.get(_t) == "high":
                    _worst = "high"
                elif _sev_map.get(_t) == "medium" and _worst != "high":
                    _worst = "medium"
            _type_cnt = _type_cnt or {"clean": 0}
            _audit_text = f"PCAP 批量检测：文件 {len(files)} 个，疑似异常 {total_anomalies} 项（" +                           "、".join(f"{k}×{v}" for k, v in sorted(_type_cnt.items())) + "）"
            if total_failed:
                _audit_text += f"，失败 {total_failed} 个"
            # 检测阶段不执行处置：有疑似发现即"待授权复核"，与报告"处置类动作需用户授权"口径一致
            _act = "待授权复核" if _worst in ("high", "medium") else "放行"
            from tools.audit_events import record_event as _re
            _re(text=_audit_text, risk_level=_worst, action=_act, cpd_onset=None, mode="pcap",
                model_version="pcap-rule-engine", latency_ms=None, source="chat", task_id=task_id)
        except Exception:
            logger.exception("record pcap audit event failed")
        lines.append("下一步建议：查看证据详情（pcap_inspect_evidence）或关联攻击链（pcap_correlate_attack_chain）。")
        lines.append("注意：以上均为\"疑似\"判断，不能确认攻击成功；处置类动作（封禁/隔离）需用户授权。")
        case_store.log_action(task_id, "pcap_batch_detect",
                              f"三路检测完成：{total_anomalies} 项网络攻击候选入库")
        lines.append(case_store.build_chain(
            task_id,
            observe=f"对任务累计 {len(files)} 个已导入 PCAP 执行检测",
            plan="pcap_batch_detect：规则路+行为路+融合路三路检测，覆盖端口扫描/暴力破解/C2心跳/数据外传/SQL注入/Web攻击载荷/DNS隧道/DoS洪泛/ARP欺骗",
            close="全部为\"疑似\"判断；L2 处置动作需用户授权",
        ))
        return "\n".join(lines)
    except Exception as e:
        logger.exception("pcap_batch_detect failed")
        return f"批量检测失败：{e}"


def _finding_summary(f: dict) -> str:
    """按 finding 实际字段生成摘要；规则路/行为路字段不同，全部 .get 防御（历史 bug：行为路
    web_attack/sql_injection/c2_beacon 缺 hits/mean_interval_sec 导致 KeyError 崩检测）。"""
    t = f["type"]
    if t == "port_scan":
        rng = f.get("port_range") or "端口范围未记录"
        dur = f.get("duration_sec")
        dur_txt = f"，持续 {dur}s" if dur is not None else ""
        return f"{f.get('attacker', '?')} -> {f.get('target', '?')} 扫描 {f.get('unique_ports', '?')} 个端口（{rng}{dur_txt}）"
    if t == "brute_force":
        return f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} 建立 {f.get('connections', '?')} 次连接，速率 {f.get('rate_per_sec', '?')}/s"
    if t == "c2_beacon":
        if "mean_interval_sec" in f:
            return (f"{f.get('src', '?')} -> {f.get('dst', '?')}:{f.get('port', '?')} 等间隔通信 "
                    f"{f.get('occurrences', '?')} 次（平均间隔 {f['mean_interval_sec']}s，变异系数 {f.get('interval_cv', '?')}）")
        return (f"{f.get('src', '?')} -> {f.get('dst', '?')}:{f.get('port', '?')} 周期性通信 {f.get('occurrences', '?')} 次"
                f"（间隔变异系数 {f.get('interval_cv', '?')}，载荷占比 {f.get('payload_ratio', '?')}）· 行为路候选")
    if t == "data_exfil":
        return f"{f.get('src', '?')} -> {f.get('dst', '?')}:{f.get('port', '?')} 上行 {f.get('upload_mb', '?')} MB"
    if t == "sql_injection":
        if "hits" in f:
            return f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} SQL 注入特征命中 {f['hits']} 次"
        return (f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} HTTP 请求行为突增"
                f"（{f.get('requests', '?')} 次，z={f.get('z_score', '?')}）· 行为路候选，需载荷复核")
    if t == "web_attack":
        if "hits" in f:
            kinds = "、".join(sorted(f.get("kinds") or []))
            return f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} Web 攻击载荷命中 {f['hits']} 次（特征：{kinds}）"
        return (f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} HTTP 请求长度分布异常"
                f"（均值 {f.get('avg_request_len', '?')}B，z={f.get('z_score', '?')}）· 行为路候选，需载荷复核")
    if t == "dns_tunnel":
        q = f.get("queries", "?")
        lc = f.get("long_label_queries", f.get("long_count", "?"))
        ud = f.get("unique_domains", "?")
        return f"{f.get('attacker', '?')} -> {f.get('target', '?')}:53 超长子域名查询 {lc} 次（共 {q} 次查询，唯一域名 {ud} 个），疑似 DNS 隐蔽信道"
    if t == "dos_flood":
        dur = f.get("duration_sec")
        dur_txt = f"{dur}s 内" if dur is not None else ""
        return f"{f.get('attacker', '?')} -> {f.get('target', '?')}:{f.get('port', '?')} {dur_txt}发送 {f.get('syn_packets', '?')} 个 SYN（速率 {f.get('rate_per_sec', '?')}/s），疑似洪泛攻击"
    if t == "arp_spoof":
        macs = "、".join(":".join(m[i:i+2] for i in range(0, len(m), 2)) for m in (f.get("macs") or []))
        return f"IP {f.get('target_ip', '?')} 被 {f.get('mac_count', '?')} 个不同 MAC 宣告（{macs}），疑似 ARP 欺骗"
    return str(f)


def _loc_desc(f: dict) -> str:
    t = f["type"]
    if "first_seen" in f and "last_seen" in f:
        try:
            return (f"时间 {time.strftime('%H:%M:%S', time.localtime(f['first_seen']))}-"
                    f"{time.strftime('%H:%M:%S', time.localtime(f['last_seen']))} (pkt时间戳区间)")
        except Exception:
            pass
    if "src" in f or "attacker" in f:
        return f"{f.get('src') or f.get('attacker', '?')} -> {f.get('dst') or f.get('target', '?')}:{f.get('port', '?')}"
    return f"pkt {f.get('first_idx', '?')}-{f.get('last_idx', '?')}"


@tool
def pcap_inspect_evidence(evidence_id: str, question: str = "这个异常的具体情况是什么？") -> str:
    """查看指定 PCAP 证据的详细信息：协议、方向、时间区间、规则命中、置信度和已知限制。"""
    try:
        task = case_store.get_current(mode="pcap")
        if task is None:
            return "错误：当前没有进行中的 PCAP 调查案件。"
        ev = case_store.get_evidence(task["task_id"], evidence_id)
        if ev is None:
            available = [e["evidence_id"] for e in task.get("evidence", [])]
            return f"错误：证据 {evidence_id} 不存在。当前可用证据: {available}"

        finding = ev.get("finding", {})
        meta = _ATTACK_META.get(finding.get("type", ""), {"name": "未知", "mitre": "-"})
        lines = [f"【证据详情】{evidence_id}", ""]
        lines.append(f"来源文件: {ev.get('file', '-')}")
        lines.append(f"攻击类型: {meta['name']} | ATT&CK: {meta['mitre']}")
        lines.append(f"证据状态: {ev.get('status')}")
        lines.append(f"摘要: {ev.get('summary')}")
        lines.append(f"位置: {ev.get('location')}")
        lines.append(f"置信度: {ev.get('confidence')}")
        lines.append("")
        lines.append("原始检测字段：")
        for k, v in finding.items():
            if k not in ("type",):
                lines.append(f"  {k}: {v}")
        lines.append("")
        lines.append("证据限制：")
        for lim in ev.get("limitations", []):
            lines.append(f"  - {lim}")
        lines.append("")
        lines.append(f"用户问题「{question}」的解读：该证据为流量元数据层面的异常（{meta['name']}），")
        lines.append("基于连接模式与阈值规则命中；由于缺少终端进程与身份日志，无法确认攻击是否成功，")
        lines.append("建议结合资产重要性判断优先级。")
        return "\n".join(lines)
    except Exception as e:
        logger.exception("pcap_inspect_evidence failed")
        return f"证据查看失败：{e}"


@tool
def pcap_correlate_attack_chain(evidence_ids: str) -> str:
    """基于多个证据 ID 关联攻击链（ATT&CK 阶段），每个阶段必须有证据支撑，缺失阶段明确标注"缺失证据"。不会凭空补全攻击链。"""
    try:
        task = case_store.get_current(mode="pcap")
        if task is None:
            return "错误：当前没有进行中的 PCAP 调查案件。"
        ids = [i.strip() for i in evidence_ids.split(",") if i.strip()]
        evidences = []
        for eid in ids:
            ev = case_store.get_evidence(task["task_id"], eid)
            if ev:
                evidences.append(ev)
        if not evidences:
            return "错误：提供的证据 ID 均不存在。请先执行 pcap_batch_detect 生成证据。"

        # ATT&CK 阶段映射
        stage_map = {
            "port_scan": ("侦察", "T1046"),
            "brute_force": ("初始访问", "T1110"),
            "c2_beacon": ("命令与控制", "T1071"),
            "data_exfil": ("数据外传", "T1041/T1048"),
        }
        stage_order = ["侦察", "初始访问", "执行", "持久化", "横向移动", "收集", "命令与控制", "数据外传", "影响"]
        found_stages = {}
        for ev in evidences:
            ftype = ev.get("finding", {}).get("type", "")
            if ftype in stage_map:
                stage, mitre = stage_map[ftype]
                found_stages.setdefault(stage, []).append((ev["evidence_id"], mitre, ev.get("confidence")))

        hypotheses = []
        lines = ["【攻击链关联结果】", ""]
        any_found = False
        for stage in stage_order:
            if stage in found_stages:
                any_found = True
                evs = found_stages[stage]
                ev_ids = [e[0] for e in evs]
                conf = max(e[2] for e in evs)
                lines.append(f"✓ {stage}（{evs[0][1]}）: 证据 {', '.join(ev_ids)} | 置信度 {conf}")
                hypotheses.append({"stage": stage, "supports": ev_ids, "missing": False, "confidence": conf})
            elif stage in ("侦察", "初始访问", "命令与控制", "数据外传"):
                lines.append(f"? {stage}: 缺失证据（当前数据不足以确认该阶段）")

        if not any_found:
            lines.append("当前证据不足以关联出任何攻击链阶段。")

        lines.append("")
        lines.append("【不确定性说明】")
        lines.append("- 攻击链基于流量元数据关联，无终端进程/身份日志，不能确认攻击成功")
        lines.append("- 缺失阶段不代表攻击没有发生，可能因采集窗口不全或流量加密")
        lines.append("- 不伪造未观测到的阶段")

        case_store.update_task(task["task_id"], hypotheses=hypotheses)
        lines.append("")
        lines.append("下一步建议：查看关键证据详情，或生成调查报告（generate_investigation_report）。")
        case_store.log_action(task["task_id"], "pcap_correlate_attack_chain",
                              f"攻击链关联完成：{len(evidence_ids)} 条证据参与研判")
        lines.append(case_store.build_chain(
            task["task_id"],
            observe=f"用户指定 {len(ids)} 条证据进行攻击链关联",
            plan="pcap_correlate_attack_chain：按 ATT&CK 阶段映射证据，缺失阶段如实标注",
            close="攻击链基于流量元数据推断，不能确认攻击成功；不伪造未观测阶段",
        ))
        return "\n".join(lines)
    except Exception as e:
        logger.exception("pcap_correlate_attack_chain failed")
        return f"攻击链关联失败：{e}"
