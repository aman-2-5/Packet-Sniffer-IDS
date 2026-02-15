from scapy.all import *
import datetime
from collections import defaultdict

# ===== CONFIG =====
INTERFACE = "eth0"
PCAP_FILE = "pcaps/capture.pcap"
LOG_FILE = "logs/traffic.log"
ALERT_FILE = "logs/alerts.log"

SCAN_THRESHOLD = 15
FLOOD_THRESHOLD = 50

# ===== DATA TRACKING =====
syn_count = defaultdict(int)
packet_count = defaultdict(int)
protocol_stats = defaultdict(int)

# ===== LOGGING =====
def log(file, msg):
    with open(file, "a") as f:
        f.write(msg + "\n")

def alert(msg):
    print("🚨 ALERT:", msg)
    log(ALERT_FILE, msg)

# ===== PACKET PROCESSOR =====
def packet_callback(packet):

    timestamp = str(datetime.datetime.now())

    # Save raw packets for forensics
    wrpcap(PCAP_FILE, packet, append=True)

    if packet.haslayer(IP):

        ip = packet[IP]
        src = ip.src
        dst = ip.dst

        packet_count[src] += 1

        info = f"{timestamp} | {src} → {dst}"

        # ===== TCP =====
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            protocol_stats["TCP"] += 1

            info += f" | TCP {tcp.sport}->{tcp.dport} Flags:{tcp.flags}"

            # SYN detection
            if tcp.flags == "S":

                syn_count[src] += 1

                if syn_count[src] > SCAN_THRESHOLD:
                    alert(f"{timestamp} | PORT SCAN detected from {src}")

                if syn_count[src] > FLOOD_THRESHOLD:
                    alert(f"{timestamp} | SYN FLOOD suspected from {src}")

        # ===== UDP =====
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            protocol_stats["UDP"] += 1

            info += f" | UDP {udp.sport}->{udp.dport}"

            # DNS detection
            if udp.dport == 53 or udp.sport == 53:
                info += " | DNS Traffic"

        # ===== ICMP =====
        elif packet.haslayer(ICMP):
            protocol_stats["ICMP"] += 1
            info += " | ICMP Packet"

        else:
            protocol_stats["OTHER"] += 1
            info += " | Other Protocol"

        print(info)
        log(LOG_FILE, info)

# ===== STATS DISPLAY =====
def print_stats():
    print("\n📊 ===== TRAFFIC STATISTICS =====")
    print("Top Active IPs:")
    for ip, count in sorted(packet_count.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"{ip}: {count} packets")

    print("\nProtocol Distribution:")
    for proto, count in protocol_stats.items():
        print(f"{proto}: {count}")

# ===== MAIN =====
print("🛡️ Industry-Level Network IDS Running...")
print("Press CTRL+C to stop\n")

try:
    sniff(iface=INTERFACE, prn=packet_callback, store=False)

except KeyboardInterrupt:
    print_stats()
    print("\n✅ Capture stopped.")
