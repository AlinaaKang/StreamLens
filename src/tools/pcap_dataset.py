"""合成 PCAP 教学数据集生成器（dpkt 写入真实二进制 pcap）。

生成 normal（HTTP 会话 / DNS 心跳 / 长连接心跳）与 attack
（端口扫描 / SSH 暴破 / C2 心跳外传 / SQL 注入拖库 / DNS 隧道 /
Web 攻击载荷 / SYN 洪泛 / ARP 欺骗）多类真实 pcap 文件，
供 PCAP 数据画像、离线评测与批量数据调查使用。

注意：这是"教学数据集"的构建能力（类似冻结样本库）——
检测器、画像与评测对这些文件做的是真实解析与真实统计，不伪造任何结论。
"""

from __future__ import annotations

import ipaddress
import os
import random
import time
from collections import OrderedDict

from typing import Any

import dpkt

DATASET_DIR = os.getenv("TS_PCAP_DATA_DIR", "/tmp/ts_pcapdata")
GROUND_TRUTH_PATH = os.path.join(DATASET_DIR, "_ground_truth.json")

_INTERNAL = "10.0.%d.%d"
_LOCAL = "10.0.0.%d"
_EXTERNAL_POOL = ["203.0.113.%d", "198.51.100.%d", "192.0.2.%d"]
_SCANNER = "203.0.113.66"
_BRUTE_FORCER = "203.0.113.77"
_C2_HOST = "198.51.100.9"


def _eth_ip_tcp(src_ip: str, dst_ip: str, sport: int, dport: int, flags: int, payload: bytes, ts: float):
    eth: Any = dpkt.ethernet.Ethernet()
    ip: Any = dpkt.ip.IP()
    tcp: Any = dpkt.tcp.TCP()
    tcp.sport = sport
    tcp.dport = dport
    tcp.seq = random.randint(10000, 90000)
    tcp.flags = flags
    tcp.data = payload
    tcp.win = 8192
    tcp.off = 5
    ip.src = bytes(map(int, src_ip.split(".")))
    ip.dst = bytes(map(int, dst_ip.split(".")))
    ip.p = dpkt.ip.IP_PROTO_TCP
    ip.len = 20 + 20 + len(payload)
    ip.ttl = 64
    ip.data = tcp
    eth.src = b"\x52\x54\x00\x12\x34\x56"
    eth.dst = b"\x52\x54\x00\xab\xcd\xef"
    eth.type = dpkt.ethernet.ETH_TYPE_IP
    eth.data = ip
    return ts, bytes(eth)


def _eth_ip_udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes, ts: float):
    eth: Any = dpkt.ethernet.Ethernet()
    ip: Any = dpkt.ip.IP()
    udp: Any = dpkt.udp.UDP()
    udp.sport = sport
    udp.dport = dport
    udp.ulen = 8 + len(payload)
    udp.data = payload
    ip.src = bytes(map(int, src_ip.split(".")))
    ip.dst = bytes(map(int, dst_ip.split(".")))
    ip.p = dpkt.ip.IP_PROTO_UDP
    ip.len = 20 + 8 + len(payload)
    ip.ttl = 64
    ip.data = udp
    eth.src = b"\x52\x54\x00\x12\x34\x56"
    eth.dst = b"\x52\x54\x00\xab\xcd\xef"
    eth.type = dpkt.ethernet.ETH_TYPE_IP
    eth.data = ip
    return ts, bytes(eth)


def _write_pcap(path: str, packets: list):
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f, linktype=dpkt.pcap.DLT_EN10MB)
        for ts, buf in packets:
            writer.writepkt(buf, ts=ts)


def _gen_normal_http(rng: random.Random, t0: float) -> list:
    """正常 HTTP 会话：GET 静态资源 + POST 登录成功 + 200 响应"""
    cli, srv = _LOCAL % (10 + rng.randint(0, 90)), "10.0.1.20"
    pkts = []
    ts = t0

    def conv(cport: int, msgs: list):
        nonlocal ts
        for direction, method, path, code in msgs:
            if direction == "req":
                body = f"{method} {path} HTTP/1.1\r\nHost: app.internal\r\nUser-Agent: Mozilla/5.0 (compatible; corp-client)\r\nCookie: SESSIONID=ok{rng.randint(1000,9999)}\r\n\r\n".encode()
                pkts.append(_eth_ip_tcp(cli, srv, cport, 80, dpkt.tcp.TH_ACK, body, ts))
            else:
                body = f"HTTP/1.1 {code} OK\r\nServer: nginx\r\nContent-Type: text/html\r\nContent-Length: 512\r\n\r\n<html>page ok</html>".encode()
                pkts.append(_eth_ip_tcp(srv, cli, 80, cport, dpkt.tcp.TH_ACK, body, ts))
            ts += rng.uniform(0.02, 0.15)

    conv(rng.randint(41000, 45000), [
        ("req", "GET", "/index.html", 200),
        ("res", "", "", 200),
        ("req", "GET", "/assets/app.js", 200),
        ("res", "", "", 200),
    ])
    conv(rng.randint(41000, 45000), [
        ("req", "POST", "/login", 200),
        ("res", "", "", 200),
        ("req", "GET", "/dashboard", 200),
        ("res", "", "", 200),
    ])
    return pkts, []


def _gen_normal_dns_heartbeat(rng: random.Random, t0: float) -> list:
    """正常 DNS 心跳：固定间隔查询内网域"""
    cli, dns_srv = _LOCAL % (20 + rng.randint(0, 80)), "10.0.0.53"
    pkts = []
    ts = t0
    domains = ["ws01.corp.local", "git.corp.local", "ci.corp.local", "mail.corp.local"]
    for i in range(12):
        name = rng.choice(domains)
        q = bytes([0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]) + b"".join(
            bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00" + b"\x00\x01\x00\x01"
        pkts.append(_eth_ip_udp(cli, dns_srv, 53000 + i, 53, q, ts))
        ts += rng.uniform(28, 33)
        ans = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + q[12:-4] + b"\x00\x01\x00\x01" + b"\xc0\x0c" + b"\x00\x01\x00\x01\x00\x00\x0e\x10" + b"\x04" + bytes([10, 0, rng.randint(1, 250), rng.randint(2, 250)])
        pkts.append(_eth_ip_udp(dns_srv, cli, 53, 53000 + i, ans, ts))
        ts += rng.uniform(0.01, 0.05)
    return pkts, []


def _gen_normal_keepalive(rng: random.Random, t0: float) -> list:
    """正常长连接小包心跳（TLS 指纹长度的二进制载荷）"""
    cli, srv = _LOCAL % (30 + rng.randint(0, 60)), "10.0.2.30"
    pkts = []
    ts = t0
    sport = rng.randint(49000, 51000)
    pkts.append(_eth_ip_tcp(cli, srv, sport, 443, dpkt.tcp.TH_SYN, b"", ts))
    ts += 0.01
    pkts.append(_eth_ip_tcp(srv, cli, 443, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b"", ts))
    ts += 0.01
    pkts.append(_eth_ip_tcp(cli, srv, sport, 443, dpkt.tcp.TH_ACK, b"", ts))
    for _ in range(24):
        ts += rng.uniform(14, 16)
        pkts.append(_eth_ip_tcp(cli, srv, sport, 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, bytes(rng.randbytes(rng.randint(40, 90))), ts))
        ts += rng.uniform(0.01, 0.06)
        pkts.append(_eth_ip_tcp(srv, cli, 443, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, bytes(rng.randbytes(rng.randint(40, 120))), ts))
    return pkts, []


def _gen_port_scan(rng: random.Random, t0: float, n_ports: int = 160, scan_delay: float = 0.012) -> list:
    """攻击：端口扫描——单源对单主机 SYN 大量不同端口（n_ports/scan_delay 可调，慢速小范围可真实逃逸）
    返回 (pkts, attack_idx)：attack_idx 为攻击包在 pkts 中的下标（定位 GT）。"""
    pkts = []
    ts = t0
    victim = _LOCAL % rng.randint(2, 60)
    sport = rng.randint(52000, 56000)
    n_ports = max(5, min(500, int(n_ports)))
    ports = sorted(rng.sample(range(20, 9000), n_ports))
    for i, p in enumerate(ports):
        pkts.append(_eth_ip_tcp(_SCANNER, victim, sport + i, p, dpkt.tcp.TH_SYN, b"", ts))
        ts += max(0.001, scan_delay * rng.uniform(0.7, 1.3))
    return pkts, list(range(len(pkts)))
    return pkts


def _gen_ssh_bruteforce(rng: random.Random, t0: float, attempts: int = 120, try_delay: float = 0.05) -> list:
    """攻击：SSH 暴破——单源对 22 端口 SYN + 失败认证包（attempts/try_delay 可调，低频少量可真实逃逸）"""
    pkts = []
    atk_idx = []
    ts = t0
    victim = _LOCAL % rng.randint(2, 60)
    sport = rng.randint(57000, 59000)
    attempts = max(5, min(400, int(attempts)))
    for i in range(attempts):
        pkts.append(_eth_ip_tcp(_BRUTE_FORCER, victim, sport + i, 22, dpkt.tcp.TH_SYN, b"", ts))
        atk_idx.append(len(pkts) - 1)
        ts += max(0.005, try_delay * rng.uniform(0.7, 1.3))
        if i % 3 == 0:
            body = b"SSH-2.0-OpenSSH_8.9\r\n\x00\x00\x00\x0c\x05auth-fail"
            pkts.append(_eth_ip_tcp(_BRUTE_FORCER, victim, sport + i, 22, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, body, ts))
            atk_idx.append(len(pkts) - 1)
            ts += 0.02
    return pkts, atk_idx


def _gen_c2_beacon(rng: random.Random, t0: float, interval: float = 30.0, jitter_pct: float = 3.3,
                   count: int = 40, exfil: bool = True) -> list:
    """攻击：C2 心跳外传——周期性到外部主机的小包+突发上传。
    interval/jitter_pct/count/exfil 可调：抖动大（CV>0.2）、次数少（<5）、时长短（<900s）
    都会被真实检测规则放过——这就是红队要找的逃逸参数。"""
    pkts = []
    atk_idx = []
    ts = t0
    victim = _LOCAL % rng.randint(2, 60)
    sport = rng.randint(51000, 52000)
    pkts.append(_eth_ip_tcp(victim, _C2_HOST, sport, 8443, dpkt.tcp.TH_SYN, b"", ts))
    ts += 0.01
    pkts.append(_eth_ip_tcp(_C2_HOST, victim, 8443, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b"", ts))
    ts += 0.01
    count = max(3, min(120, int(count)))
    jitter = max(0.0, min(80.0, float(jitter_pct)))
    for i in range(count):
        iv = interval * (1.0 + rng.uniform(-jitter / 100.0, jitter / 100.0))
        ts += max(1.0, iv)
        beacon = bytes(rng.randbytes(64))
        pkts.append(_eth_ip_tcp(victim, _C2_HOST, sport, 8443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, beacon, ts))
        atk_idx.append(len(pkts) - 1)
        ts += rng.uniform(0.02, 0.05)
        pkts.append(_eth_ip_tcp(_C2_HOST, victim, 8443, sport, dpkt.tcp.TH_ACK, b"", ts))
        if exfil and i % 5 == 4:
            ts += 0.1
            blob = bytes(rng.randbytes(rng.randint(8000, 15000)))  # 突发外传
            pkts.append(_eth_ip_tcp(victim, _C2_HOST, sport, 8443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, blob, ts))
            atk_idx.append(len(pkts) - 1)
    return pkts, atk_idx


def _gen_sql_dump(rng: random.Random, t0: float, n_req: int = 30) -> list:
    """攻击：明文 HTTP SQL 注入拖库——同会话内编码注入参数 + 大响应（n_req < 3 可真实逃逸）"""
    pkts = []
    atk_idx = []
    ts = t0
    cli, srv = _LOCAL % rng.randint(2, 60), "10.0.3.80"
    sport = rng.randint(46000, 47000)
    pkts.append(_eth_ip_tcp(cli, srv, sport, 8080, dpkt.tcp.TH_SYN, b"", ts)); ts += 0.01
    pkts.append(_eth_ip_tcp(srv, cli, 8080, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK, b"", ts)); ts += 0.01
    n_req = max(1, min(80, int(n_req)))
    for i in range(n_req):
        payload = (f"GET /api/users?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users%20LIMIT%20100%20OFFSET%20{i * 100} HTTP/1.1\r\n"
                   f"Host: erp.internal\r\n\r\n").encode()
        pkts.append(_eth_ip_tcp(cli, srv, sport, 8080, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload, ts))
        atk_idx.append(len(pkts) - 1)
        ts += rng.uniform(0.05, 0.2)
        body = f"HTTP/1.1 200 OK\r\nContent-Length: {rng.randint(8000, 20000)}\r\n\r\n" + ("row,u,p\n" * rng.randint(150, 400))
        pkts.append(_eth_ip_tcp(srv, cli, 8080, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, body.encode(), ts))
        atk_idx.append(len(pkts) - 1)
    return pkts, atk_idx


def _eth_arp(op: int, sha: str, spa: str, tha: str, tpa: str, ts: float):
    """ARP 帧（二层 ARP 欺骗场景专用）"""
    arp: Any = dpkt.arp.ARP()
    arp.htype = 1
    arp.ptype = 0x0800
    arp.hln = 6
    arp.pln = 4
    arp.op = op
    arp.sha = bytes.fromhex(sha.replace(":", ""))
    arp.spa = bytes(map(int, spa.split(".")))
    arp.tha = bytes.fromhex(tha.replace(":", ""))
    arp.tpa = bytes(map(int, tpa.split(".")))
    eth: Any = dpkt.ethernet.Ethernet()
    eth.src = arp.sha
    eth.dst = b"\xff" * 6 if op == dpkt.arp.ARP_OP_REQUEST else arp.tha
    eth.type = dpkt.ethernet.ETH_TYPE_ARP
    eth.data = arp
    return ts, bytes(eth)


def _b32(rng, n: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(n))


def _gen_dns_tunnel(rng, t0: float):
    """DNS 隧道：大量超长随机子域名 TXT 查询（隐蔽信道数据外传）"""
    pkts = []
    atk_idx = []
    src = _INTERNAL % (rng.randint(1, 9), rng.randint(10, 99))
    for i in range(40):
        qname = f"{_b32(rng, rng.randint(26, 38))}.tunnel-c2.example.com"
        d = dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name=qname, type=dpkt.dns.DNS_TXT)])
        pkts.append(_eth_ip_udp(src, "8.8.8.8", 40000 + i, 53, d.pack(), t0 + i * 0.3))
        atk_idx.append(len(pkts) - 1)
    for i in range(5):  # 混入正常域名查询
        d = dpkt.dns.DNS(qd=[dpkt.dns.DNS.Q(name="portal.corp.internal", type=dpkt.dns.DNS_A)])
        pkts.append(_eth_ip_udp(src, "8.8.8.8", 41000 + i, 53, d.pack(), t0 + 13.0 + i * 0.5))
    return pkts, atk_idx


_WEB_PAYLOADS = [
    "GET /static/%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
    "GET /download?file=%2e%2e%2f%2e%2e%2fetc%2fshadow HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
    "GET /api/ping?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
    "GET /api/ping?host=127.0.0.1%3Bls%20-la%20%2F HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
    "GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
    "GET /page?name=x%22%20onerror%3Dalert%281%29 HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n",
]


def _gen_web_attack(rng, t0: float):
    """Web 攻击载荷：路径遍历 / 命令注入 / XSS 混合（URL 编码）"""
    pkts = []
    atk_idx = []
    src = _INTERNAL % (rng.randint(1, 9), rng.randint(10, 99))
    dst = rng.choice(_EXTERNAL_POOL) % 42
    for i in range(15):
        pkts.append(_eth_ip_tcp(src, dst, 50000 + i, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                                _WEB_PAYLOADS[i % len(_WEB_PAYLOADS)].encode(), t0 + i * 0.4))
        atk_idx.append(len(pkts) - 1)
    for i in range(10):  # 正常业务请求（确保画像可区分攻击面）
        pkts.append(_eth_ip_tcp(src, dst, 51000 + i, 80, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                                f"GET /assets/app{i % 3}.js HTTP/1.1\r\nHost: web.corp.example.com\r\n\r\n".encode(),
                                t0 + 7.0 + i * 0.2))
    return pkts, atk_idx


def _gen_syn_flood(rng, t0: float):
    """SYN 洪泛：高速率纯 SYN 洪水（DoS）"""
    pkts = []
    src = _INTERNAL % (rng.randint(1, 9), rng.randint(10, 99))
    dst = rng.choice(_EXTERNAL_POOL) % 30
    for i in range(400):
        pkts.append(_eth_ip_tcp(src, dst, 30000 + (i % 800), 80, dpkt.tcp.TH_SYN, b"", t0 + i * 0.002))
    return pkts, list(range(len(pkts)))


def _gen_arp_spoof(rng, t0: float):
    """ARP 欺骗：网关/受害者 IP 被攻击者 MAC 重复宣告（中间人）"""
    gw_mac, victim_mac, atk_mac = "52:54:00:aa:00:01", "52:54:00:aa:00:02", "52:54:00:be:ef:03"
    gw_ip, victim_ip = "10.0.0.1", "10.0.0.30"
    pkts = []
    atk_idx = []
    t = t0
    for _ in range(8):  # 网关 IP 被攻击者 MAC 宣告
        pkts.append(_eth_arp(dpkt.arp.ARP_OP_REPLY, atk_mac, gw_ip, victim_mac, victim_ip, t))
        atk_idx.append(len(pkts) - 1)
        t += 0.5
    for _ in range(6):  # 受害者 IP 被攻击者 MAC 宣告
        pkts.append(_eth_arp(dpkt.arp.ARP_OP_REPLY, atk_mac, victim_ip, gw_mac, gw_ip, t))
        atk_idx.append(len(pkts) - 1)
        t += 0.5
    for _ in range(6):  # 正常 ARP 请求
        pkts.append(_eth_arp(dpkt.arp.ARP_OP_REQUEST, victim_mac, victim_ip, "00:00:00:00:00:00", gw_ip, t)); t += 0.5
    src = _INTERNAL % (2, 20)  # 混入正常业务流量
    for i in range(15):
        pkts.append(_eth_ip_tcp(src, gw_ip, 52000 + i, 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH,
                                b"\x16\x03\x01\x00\x40" + bytes(60), t + i * 0.3))
    return pkts, atk_idx


# 场景表：(name, kind, generator, expected_attack_types)
_SCENARIOS = [
    ("http_session", "normal", _gen_normal_http, []),
    ("dns_heartbeat", "normal", _gen_normal_dns_heartbeat, []),
    ("keepalive_443", "normal", _gen_normal_keepalive, []),
    ("port_scan", "attack", _gen_port_scan, ["port_scan"]),
    ("ssh_bruteforce", "attack", _gen_ssh_bruteforce, ["bruteforce"]),
    ("c2_beacon", "attack", _gen_c2_beacon, ["c2"]),
    ("sql_dump", "attack", _gen_sql_dump, ["sql_injection"]),
    ("dns_tunnel", "attack", _gen_dns_tunnel, ["dns_tunnel"]),
    ("web_attack", "attack", _gen_web_attack, ["web_attack"]),
    ("syn_flood", "attack", _gen_syn_flood, ["dos_flood"]),
    ("arp_spoof", "attack", _gen_arp_spoof, ["arp_spoof"]),
]

# 每场景变体数（模拟数据集规模）
_VARIANTS = 3

# ground truth 结构版本（v2：匿名文件名 + 攻击包定位区间）
GT_VERSION = 2


def _idx_to_ranges(idxs: list) -> list:
    """把包索引列表压缩为连续区间 [[start, end], ...]（定位 GT 存储格式）"""
    if not idxs:
        return []
    s = sorted(set(int(i) for i in idxs))
    ranges, start, prev = [], s[0], s[0]
    for i in s[1:]:
        if i == prev + 1:
            prev = i
            continue
        ranges.append([start, prev])
        start = prev = i
    ranges.append([start, prev])
    return ranges


def ensure_dataset(force: bool = False) -> dict:
    """确保数据集存在；返回清单。所有文件均为真实 pcap 二进制。
    文件名匿名（sample_NNN.pcap），场景标签与攻击包定位只存 _ground_truth.json
    （文件名/路径不作输入、标签或模型特征）。"""
    if not force and os.path.isdir(DATASET_DIR) and len(os.listdir(DATASET_DIR)) > 0:
        gt = ground_truth()
        if gt.get("gt_version") == GT_VERSION and gt.get("items"):
            info = {"dir": DATASET_DIR, "files": sorted(it["file"] for it in gt["items"]),
                    "total": len(gt["items"])}
            return info
        force = True  # 旧版数据集（带场景名文件名/无定位 GT）→ 重建
    os.makedirs(DATASET_DIR, exist_ok=True)
    # 重建前清空旧文件，避免匿名化后残留旧命名文件
    for old in os.listdir(DATASET_DIR):
        try:
            os.remove(os.path.join(DATASET_DIR, old))
        except OSError:
            pass
    rng_master = random.Random(20250908)
    truth = []
    idx = 0
    for name, kind, gen, attacks in _SCENARIOS:
        for v in range(_VARIANTS):
            rng = random.Random(rng_master.random())
            t0 = 1750000000 + idx * 600.0
            pkts, atk_idx = gen(rng, t0)
            fname = f"sample_{idx:03d}.pcap"   # 匿名文件名：不泄露场景/标签
            _write_pcap(os.path.join(DATASET_DIR, fname), pkts)
            truth.append({
                "file": fname,
                "scenario": name,           # 场景名只在标签清单中（评测侧脱敏标签）
                "kind": kind,
                "attack_types": attacks,
                "attack_packet_ranges": _idx_to_ranges(atk_idx),
                "attack_packet_count": len(atk_idx),
                "packets": len(pkts),
                "duration": round(max((p[0] for p in pkts), default=t0) - t0, 3),
            })
            idx += 1
    import json
    with open(GROUND_TRUTH_PATH, "w", encoding="utf-8") as f:
        json.dump({"gt_version": GT_VERSION, "generated_at": int(time.time()),
                   "sampling": "synthetic_frozen_v2", "items": truth}, f, ensure_ascii=False, indent=1)
    info = {"dir": DATASET_DIR, "files": sorted(it["file"] for it in truth), "total": len(truth)}
    return info


def ground_truth() -> dict:
    if os.path.isfile(GROUND_TRUTH_PATH):
        import json
        with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
            return json.load(f)
    return {"gt_version": None, "generated_at": None, "items": []}


if __name__ == "__main__":
    print(ensure_dataset(force=False))
