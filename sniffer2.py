import socket
import struct
import argparse
from collections import defaultdict
from datetime import datetime

# === Logger Function ===
def log_alert(msg, log_file):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    entry = f"{timestamp} {msg}"
    print(entry)
    if log_file:
        with open(log_file, "a") as log:
            log.write(entry + "\n")

# === Parse CLI Arguments ===
parser = argparse.ArgumentParser(description="Packet Sniffer + Basic IDS")
parser.add_argument('--ip', type=str, required=True, help='Local IP address to bind to')
parser.add_argument('--log', type=str, default='alerts.log', help='Log file path for alerts')
args = parser.parse_args()

ip_address = args.ip
log_file = args.log

# === IDS Settings ===
suspicious_ports = [4444, 1337, 6667, 23, 21]
blacklisted_ips = ['192.168.1.200', '10.10.10.10', '8.8.8.8']
syn_tracker = defaultdict(int)

# === Setup Socket ===
host_name = socket.gethostname()
print(f"Host: {host_name}")
print(f"Binding to: {ip_address}")

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
sniffer.bind((ip_address, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

log_alert("[*] Sniffing started... Press CTRL+C to stop", log_file)

try:
    while True:
        raw_packet, addr = sniffer.recvfrom(65565)
        ip_header = raw_packet[0:20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        ihl = version_ihl & 0xF
        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        ip_header_length = ihl * 4

        # TCP
        if protocol == 6:
            tcp_header = raw_packet[ip_header_length:ip_header_length + 20]
            tcph = struct.unpack('!HHLLBBHHH', tcp_header)

            src_port = tcph[0]
            dst_port = tcph[1]
            flags = tcph[5]
            tcp_header_length = (tcph[4] >> 4) * 4
            data_offset = ip_header_length + tcp_header_length
            data = raw_packet[data_offset:]

            print(f"\n[+] TCP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}")

            if dst_port in suspicious_ports or src_port in suspicious_ports:
                log_alert(f"🚨 Suspicious port detected: {src_port} → {dst_port}", log_file)

            if src_ip in blacklisted_ips or dst_ip in blacklisted_ips:
                log_alert(f"🚨 Blacklisted IP detected: {src_ip} or {dst_ip}", log_file)

            if flags == 0x02:  # SYN flag
                syn_tracker[src_ip] += 1
                if syn_tracker[src_ip] > 20:
                    log_alert(f"🚨 SYN scan suspected from {src_ip} (Count: {syn_tracker[src_ip]})", log_file)

            if data:
                print("[Payload]:", data[:50])

        # UDP
        elif protocol == 17:
            udp_header = raw_packet[ip_header_length:ip_header_length + 8]
            udph = struct.unpack('!HHHH', udp_header)
            src_port, dst_port = udph[0], udph[1]
            print(f"\n[+] UDP Packet: {src_ip}:{src_port} → {dst_ip}:{dst_port}")

        # ICMP
        elif protocol == 1:
            print(f"\n[+] ICMP Packet: {src_ip} → {dst_ip}")

except KeyboardInterrupt:
    print("\n[!] Sniffing stopped by user.")
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
