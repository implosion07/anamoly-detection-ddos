import subprocess
import time
from collections import defaultdict
from scapy.all import sniff, IP

# settings (changable)
TARGET_IP = "192.168.162.132"
SINGLE_PACKET_THRESHOLD = 100   # threshold for single IP flood
MASS_UNIQUE_IP_THRESHOLD = 50   # threshold for mass IP flood
MONITOR_INTERFACE = "eth0"      # our network interface

# storage
packet_counts = defaultdict(int)  # counting packets per source IP
blocked_ips = set()               # tracking already blocked IPs
unique_ips = set()                # unique IPs targeting TARGET_IP

def block_ip(ip):
    if ip not in blocked_ips:
        print(f" Blocking IP {ip} for attacking {TARGET_IP}")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-d", TARGET_IP, "-j", "DROP"])
        blocked_ips.add(ip)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if dst_ip == TARGET_IP:
            packet_counts[src_ip] += 1
            unique_ips.add(src_ip)

def monitor():
    while True:
        # clear previous counts
        packet_counts.clear()
        unique_ips.clear()
        
        # sniff packets for 1 second
        sniff(iface=MONITOR_INTERFACE, prn=packet_callback, timeout=1, store=0)
        
        # check Single IP Floods
        for ip, count in packet_counts.items():
            if count > SINGLE_PACKET_THRESHOLD and ip not in blocked_ips:
                print(f"[ALERT] Single IP flood detected from {ip} with {count} packets!")
                block_ip(ip)

        # check Mass IP Flood
        if len(unique_ips) > MASS_UNIQUE_IP_THRESHOLD:
            print(f"[ALERT] Mass IP flood detected! {len(unique_ips)} unique IPs targeting {TARGET_IP}!")
            # block all involved IPs
            for ip in unique_ips:
                if ip not in blocked_ips:
                    block_ip(ip)

if __name__ == "__main__":
    print(f"Monitoring traffic targeting {TARGET_IP} on interface {MONITOR_INTERFACE}...")
    monitor()
