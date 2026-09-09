# 网络与 PCAP 分析知识库

## PCAP 文件基础

PCAP（Packet Capture）是网络流量捕获的标准格式，记录链路上传输的数据包。分析要点包括：五元组（源IP、源端口、目的IP、目的端口、协议）、时间戳、包大小、TCP 标志位（SYN/ACK/FIN/RST）。

## 端口扫描（Port Scanning）

特征：单一源 IP 在短时间内向同一目标（或网段）的大量不同端口发起连接。
- TCP SYN 扫描：大量 SYN 包但无完整三次握手（SYN 后无 ACK，或收到 RST）
- TCP Connect 扫描：完整握手后立即断开
- 判定阈值参考：单源 IP 在 60 秒内向同一目标发起 20+ 个不同目的端口的 SYN，可判定为扫描行为
- MITRE ATT&CK 映射：T1046 Network Service Scanning

## 暴力破解（Brute Force）

特征：同一源 IP 对同一目标的认证端口（22 SSH、3389 RDP、21 FTP、23 Telnet、3306 MySQL）高频重复连接。
- 判定阈值参考：60 秒内同一源目对建立 50+ 次连接，或登录尝试密集出现
- MITRE ATT&CK 映射：T1110 Brute Force

## C2 心跳（Command and Control Beacon）

特征：受感染主机与 C2 服务器之间的周期性通信。
- 通信间隔高度规律（如每 30 秒一次，间隔方差极小）
- 每次通信数据量相近且较小（心跳包通常几十到几百字节）
- 长时间持续（远超正常会话时长）
- 判定要点：至少 5 次以上等间隔通信（允许少量突发离群间隔，以主周期中位数计算变异系数），且持续会话超过 15 分钟，间隔变异系数 < 0.2
- MITRE ATT&CK 映射：T1071 Application Layer Protocol / T1043 Commonly Used Port

## 数据外传（Data Exfiltration）

特征：单连接上行字节数异常大，或短时间向外部传输大量数据。
- 判定阈值参考：单连接上行 > 1MB，或单源 IP 总上行在短时间内异常突出
- 常见通道：HTTP POST、DNS 隧道、FTP、云盘 API
- MITRE ATT&CK 映射：T1048 Exfiltration Over Alternative Protocol / T1041 Exfiltration Over C2 Channel

## 横向移动（Lateral Movement）

特征：内网主机之间的异常服务访问（如 workstation 访问大量其他主机的 445 SMB、3389 RDP）。
- MITRE ATT&CK 映射：T1021 Remote Services

## 分析限制（诚实边界）

- 仅有 PCAP 时，无法看到终端进程、身份账号、完整加密内容，只能给出"疑似"判断
- 加密流量（TLS）无法直接读取载荷，只能基于元数据（连接模式、包大小、时序）分析
- 无终端进程、身份日志或完整网络上下文时，不能声称攻击成功或确认攻击者身份
- 证据不足时必须明确标注"证据不足"，不得凭空补全攻击链
