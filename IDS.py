from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# A dictionary to track SYN packets and their timestamps for SYN flood detection
syn_flood_tracker = defaultdict(list)

# A dictionary to track port scan attempts (IP -> [list of attempted ports])
port_scan_tracker = defaultdict(list)

# Time window for detecting port scanning activity (e.g., 10 seconds)
SCAN_TIME_WINDOW = 10
SYN_FLOOD_TIME_WINDOW = 5  # Seconds for detecting SYN flood

# Function to detect anomalies based on network patterns
def detect_anomalies(packet):
    # Ensure the packet has IP and TCP layers
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_flags = packet[TCP].flags
        packet_length = len(packet)

        # Example 1: SYN Flood (detecting multiple SYN packets in a short time)
        if tcp_flags == "S":
            syn_flood_tracker[ip_src].append(time.time())

            # Remove timestamps older than SYN_FLOOD_TIME_WINDOW seconds
            syn_flood_tracker[ip_src] = [ts for ts in syn_flood_tracker[ip_src] if time.time() - ts <= SYN_FLOOD_TIME_WINDOW]

            if len(syn_flood_tracker[ip_src]) > 50:  # Threshold for SYN flood attack detection (50 SYN packets)
                print(f"[SYN Flood Detection] High SYN packet count from {ip_src} within {SYN_FLOOD_TIME_WINDOW} seconds")

        # Example 2: Port Scanning (detecting multiple attempts to different ports)
        if packet[IP].src != ip_dst:
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            port_scan_tracker[src_ip].append((time.time(), dst_port))

            # Remove timestamps older than SCAN_TIME_WINDOW seconds
            port_scan_tracker[src_ip] = [entry for entry in port_scan_tracker[src_ip] if time.time() - entry[0] <= SCAN_TIME_WINDOW]

            # If the number of unique ports scanned exceeds a threshold, consider it a port scan
            unique_ports = len(set(entry[1] for entry in port_scan_tracker[src_ip]))
            if unique_ports > 10:
                print(f"[Port Scan Detection] Potential port scan detected from {src_ip} targeting {unique_ports} different ports")

        # Example 3: Large Packet (potential data exfiltration)
        if packet_length > 1500:
            print(f"[Large Packet Detection] Large packet from {ip_src} to {ip_dst}, size: {packet_length} bytes")

# Function to handle the packets and apply anomaly detection
def packet_handler(packet):
    # Detect anomalies in each packet
    detect_anomalies(packet)
    
    # Print packet summary
    print(packet.summary())

# Start sniffing packets on the eth0 interface
print("[INFO] Sniffing traffic on eth0...")
sniff(iface="eth0", store=False, prn=packet_handler)
