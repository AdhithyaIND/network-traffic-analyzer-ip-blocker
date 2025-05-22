# network_traffic_analyzer.py

from scapy.all import sniff, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
from collections import defaultdict
import csv
import time
import os
import subprocess

# Packet tracking
packet_counts = defaultdict(int)
traffic_over_time = []
packet_rate = defaultdict(list)
blocked_ips = set()

BLOCK_THRESHOLD = 100  # Packets per 10 seconds

# CSV logger
def log_packet(pkt):
    with open("packet_log.csv", "a", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            time.strftime("%Y-%m-%d %H:%M:%S"),
            pkt[IP].src if IP in pkt else "N/A",
            pkt[IP].dst if IP in pkt else "N/A",
            pkt.proto if IP in pkt else "N/A"
        ])

# Packet handler with rate tracking and blocking
def packet_handler(pkt):
    if IP in pkt:
        proto = pkt[IP].proto
        protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")
        src_ip = pkt[IP].src

        packet_counts[protocol] += 1
        log_packet(pkt)
        traffic_over_time.append(time.time())

        # Track rate per IP
        now = time.time()
        packet_rate[src_ip].append(now)
        packet_rate[src_ip] = [t for t in packet_rate[src_ip] if now - t <= 10]

        if len(packet_rate[src_ip]) > BLOCK_THRESHOLD and src_ip not in blocked_ips:
            print(f"[!] Detected potential DoS from {src_ip} — Blocking...")
            try:
                subprocess.run([
                    "powershell", "-Command",
                    f"New-NetFirewallRule -DisplayName 'Block {src_ip}' -Direction Inbound -RemoteAddress {src_ip} -Action Block"
                ])
                blocked_ips.add(src_ip)
            except Exception as e:
                print(f"[X] Failed to block IP {src_ip}: {e}")

# Graphs
def draw_protocol_graph():
    protocols = list(packet_counts.keys())
    counts = list(packet_counts.values())

    plt.figure(figsize=(8, 5))
    plt.bar(protocols, counts, color='skyblue')
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Packet Count")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.show()

def draw_traffic_over_time():
    if not traffic_over_time:
        return

    start_time = traffic_over_time[0]
    timeline = [round(ts - start_time, 1) for ts in traffic_over_time]

    per_second = defaultdict(int)
    for t in timeline:
        per_second[int(t)] += 1

    x = sorted(per_second.keys())
    y = [per_second[t] for t in x]

    plt.figure(figsize=(10, 5))
    plt.plot(x, y, marker='o', linestyle='-', color='green')
    plt.title("Network Traffic Over Time")
    plt.xlabel("Time (s)")
    plt.ylabel("Packets per Second")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.tight_layout()
    plt.show()

# Main
def main():
    print("[+] Starting packet capture... Press Ctrl+C to stop.")
    try:
        sniff(prn=packet_handler, store=0, timeout=30)
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted.")

    print("\n[+] Drawing graphs...")
    draw_protocol_graph()
    draw_traffic_over_time()
    print("[+] Done.")

if __name__ == '__main__':
    with open("packet_log.csv", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Timestamp", "Source IP", "Destination IP", "Protocol"])
    main()
