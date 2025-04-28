#!/bin/bash
#
# DDoS Protection Firewall Configuration Script
# This script sets up iptables rules to protect against common DDoS attacks
#

# check for running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# extract target IP and interface from command line
if [ $# -lt 2 ]; then
  echo "Usage: $0 <interface> <target_ip> [rate_limit] [time_window]"
  exit 1
fi

INTERFACE=$1
TARGET_IP=$2
RATE_LIMIT=${3:-1000}  # defaults can change
TIME_WINDOW=${4:-10}   # defaults can change

echo "Setting up DDoS protection for $TARGET_IP on interface $INTERFACE"
echo "Rate limit: using default"

# reset the iptables
echo "Resetting iptables rules..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# set the default policies
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# make a custom chains for DDoS protection
iptables -N DDOS_PROTECT
iptables -N RATE_LIMIT
iptables -N PORT_SCAN

# implemeting the protection to all incoming traffic to target IP
iptables -A INPUT -d $TARGET_IP -j DDOS_PROTECT

# basic protection against SYN flood
echo "Setting up SYN flood protection..."
iptables -A DDOS_PROTECT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A DDOS_PROTECT -p tcp --syn -j DROP

# against ICMP flood (ping flood)
echo "Setting up ICMP flood protection..."
iptables -A DDOS_PROTECT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A DDOS_PROTECT -p icmp --icmp-type echo-request -j DROP

#  against port scanning
echo "Setting up port scan protection..."
iptables -A DDOS_PROTECT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j ACCEPT
iptables -A DDOS_PROTECT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j DROP

# rate limiting per source IP
echo "Setting up rate limiting per source IP..."
iptables -A DDOS_PROTECT -m recent --name DDOS --set
iptables -A DDOS_PROTECT -m recent --name DDOS --update --seconds $TIME_WINDOW --hitcount $RATE_LIMIT -j DROP


# dropping  invalid packets
echo "Setting up invalid packet filtering..."
iptables -A DDOS_PROTECT -m state --state INVALID -j DROP

# allowing established and related connections
iptables -A DDOS_PROTECT -m state --state ESTABLISHED,RELATED -j ACCEPT

# especial rule for DNS amplification protection (if target runs DNS)
echo "Setting up DNS amplification protection..."
iptables -A DDOS_PROTECT -p udp --dport 53 -m hashlimit \
  --hashlimit-name DNS_LIMIT \
  --hashlimit-mode srcip \
  --hashlimit-srcmask 24 \
  --hashlimit-above 30/minute \
  --hashlimit-burst 5 \
  --hashlimit-htable-size 32768 \
  --hashlimit-htable-max 32768 \
  --hashlimit-htable-expire 60000 \
  -j DROP



# firewall default rule - everything else is allowed
iptables -A DDOS_PROTECT -j ACCEPT

# saving the rules
echo "Saving iptables rules..."
if command -v iptables-save >/dev/null; then
  iptables-save > /etc/iptables/rules.v4 || \
  iptables-save > /etc/iptables.rules || \
  echo "Rules saved in memory only. Install iptables-persistent to save permanently."
else
  echo "iptables-save not found. Rules saved in memory only."
  echo "To save permanently, install iptables-persistent."
fi

echo "Done! DDoS protection is now active."

