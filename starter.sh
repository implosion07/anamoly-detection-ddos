#!/bin/bash

# running with sudo
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Trying with sudo..."
   sudo "$0" "$@"
   exit $?
fi

# start 1st script
gnome-terminal -- bash -c "./setup_firewall.sh eth0 192.168.162.132; exec bash"
sleep 3

# starting second script in a new terminal
gnome-terminal -- bash -c "python3 ddos_monitor_app.py --interface eth0 --target 192.168.162.132; exec bash"
sleep 3

# starting third script in a new terminal
gnome-terminal -- bash -c "python3 tracker.py; exec bash"
