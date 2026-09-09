"""生成测试用 PCAP 文件：包含端口扫描、暴力破解、C2 心跳、正常流量、数据外传 5 类场景（一次性脚本）"""
import os
import struct
import dpkt
import socket

OUT_DIR = os.path.join(os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects"), "assets", "test_data")
os.makedirs(OUT_DIR, exist_ok=True)

def eth_ip_tcp(src_ip, dst_ip, sport, dport, flags, payload=b"", seq=1):
    """正确构造 Ethernet/IP/TCP 三层封包（必须显式设置 ip.p = IP_PROTO_TCP）"""
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, flags=flags, win=8192)
    tcp.data = payload
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src_ip),
        dst=socket.inet_aton(dst_ip),
        p=dpkt.ip.IP_PROTO_TCP,  # 关键：显式声明上层协议为 TCP，否则解析端无法识别
        ttl=64,
    )
    ip.data = tcp
    ip.len = len(ip)  # type: ignore
    eth = dpkt.ethernet.Ethernet()
    eth.data = ip
    eth.type = dpkt.ethernet.ETH_TYPE_IP
    return eth


def write_pcap(path, packets):
    with open(path, "wb") as f:
        writer = dpkt.pcap.Writer(f)
        ts_base = 1725700000.0
        for i, (dt, pkt) in enumerate(packets):
            writer.writepkt(pkt, ts=ts_base + dt)
    print(f"[OK] {path} ({len(packets)} packets)")


# 1. 端口扫描：10.0.0.66 -> 192.168.1.10 大量不同端口 SYN
packets = []
for i in range(45):
    dport = 1000 + i * 7
    packets.append((i * 0.5, eth_ip_tcp("10.0.0.66", "192.168.1.10", 40000 + i, dport, dpkt.tcp.TH_SYN)))
    if i % 3 == 0:  # 部分 RST 响应
        packets.append((i * 0.5 + 0.01, eth_ip_tcp("192.168.1.10", "10.0.0.66", dport, 40000 + i, dpkt.tcp.TH_RST)))
write_pcap(os.path.join(OUT_DIR, "port_scan.pcap"), packets)

# 2. 暴力破解：10.0.0.77 -> 192.168.1.20:22 高频连接（真实握手：SYN -> SYN|ACK -> ACK+载荷）
packets = []
for i in range(80):
    sport = 50000 + i
    t = i * 0.4
    packets.append((t, eth_ip_tcp("10.0.0.77", "192.168.1.20", sport, 22, dpkt.tcp.TH_SYN)))
    packets.append((t + 0.01, eth_ip_tcp("192.168.1.20", "10.0.0.77", 22, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
    packets.append((t + 0.02, eth_ip_tcp("10.0.0.77", "192.168.1.20", sport, 22, dpkt.tcp.TH_ACK, payload=b"SSH-2.0-OpenSSH_8.9\r\n")))
    packets.append((t + 0.03, eth_ip_tcp("192.168.1.20", "10.0.0.77", 22, sport, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"Password: ")))
    packets.append((t + 0.04, eth_ip_tcp("10.0.0.77", "192.168.1.20", sport, 22, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=f"user{i}:pass{i}\r\n".encode())))
write_pcap(os.path.join(OUT_DIR, "brute_force.pcap"), packets)

# 3. C2 心跳：10.0.0.88 -> 45.33.22.11:443 等间隔小包
packets = []
for i in range(20):
    packets.append((i * 30.0, eth_ip_tcp("10.0.0.88", "45.33.22.11", 51000, 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"\x17\x03\x03\x00\x40" + b"A" * 60)))
    packets.append((i * 30.0 + 0.05, eth_ip_tcp("45.33.22.11", "10.0.0.88", 443, 51000, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=b"\x17\x03\x03\x00\x20" + b"B" * 28)))
write_pcap(os.path.join(OUT_DIR, "c2_beacon.pcap"), packets)

# 4. 正常流量：内网 web 访问，少量请求、间隔随机
import random
random.seed(42)
packets = []
t = 0.0
for i in range(12):
    t += random.uniform(20, 200)
    sport = random.randint(20000, 60000)
    packets.append((t, eth_ip_tcp("192.168.1.30", "93.184.216.34", sport, 443, dpkt.tcp.TH_SYN)))
    packets.append((t + 0.02, eth_ip_tcp("93.184.216.34", "192.168.1.30", 443, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
    packets.append((t + 0.03, eth_ip_tcp("192.168.1.30", "93.184.216.34", sport, 443, dpkt.tcp.TH_ACK)))
    payload = b"\x17\x03\x03\x01\x00" + b"C" * random.randint(200, 4000)
    packets.append((t + 0.04, eth_ip_tcp("192.168.1.30", "93.184.216.34", sport, 443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload)))
write_pcap(os.path.join(OUT_DIR, "normal_traffic.pcap"), packets)

# 5. 数据外传：10.0.0.99 -> 203.0.113.5:8443 大流量上行（30 包 x 60KB = 1.8MB）
packets = []
for i in range(30):
    payload = b"\x17\x03\x03\xea\x5f" + b"D" * 60000  # ~60KB each, 总计 ~1.8MB
    packets.append((i * 0.1, eth_ip_tcp("10.0.0.99", "203.0.113.5", 52000, 8443, dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, payload=payload)))
write_pcap(os.path.join(OUT_DIR, "data_exfil.pcap"), packets)

print("done")
