# Anomaly Detection for DDoS Attack Defense in Virtual Environment 

This project is a comprehensive solution designed to detect and prevent Distributed Denial of Service (DDoS) attacks in case of cloud servers. This work protects servers by monitoring the network traffic going to server, detecting attack patterns if necessary and implementing defensive measures to ensure system remains secure. The data collected then can be used to detect anamoly using an autoencoder.

## Overview

The current state of the project addresses common DDoS attack vectors including:
- UDP Flood
- TCP SYN Flood
- HTTP Flood
- ICMP Flood

The system leverages real-time monitoring and packet analysis through graphs along with a configurable firewall and a rate-limiting logic to prevent such attacks and to protect vulnerable cloud systems.

## Project Structure

```
/
├── attack/
│   └── attacker.sh       # script for simulating various DDoS attacks
├── setup_firewall.sh     # script to configure and start protective firewall
├── ddos_monitor_app.py   # GUI based application for monitoring network traffic
├── tracker.py            # attack detection through rate-limiting
├── starter.sh            # a script to launch all components
└── requirements.txt      # Python dependencies to installed 
```

## Setup Instructions

### Prerequisites

1. Please install required Python packages: `pip install -r requirements.txt`
3. Set up your test environment with precautions:
   - Victim: Metasploitable2 Linux VM
   - Attackers: Multiple Kali Linux VMs
   
### Environment

- We need a Linux environment to run this project.

### Installation

1. Make scripts executable:
   ```
   chmod +x starter.sh setup_firewall.sh attack/attacker.sh
   ```

## Usage

The project can eb run in two ways:

### Automatic Startup (Recommended)

Run the starter script to launch all components with default configurations of the parameters:

```bash
./starter.sh
```

### Manual Configuration

For custom configurations, you can run each component separately:

1. Start the firewall:
   ```bash
   ./setup_firewall.sh <target ip> [rate] [time-window-frame] 
   ```

2. Launch the monitoring application:
   ```bash
   sudo python3 ddos_monitor_app.py --interface <interface> --target <target>
   ```

3. Run the attack tracker:
   ```bash
   sudo python3 tracker.py 
   ```

### Simulating Attacks

The attacker script can be copied to a separate machine to simulate DDoS attacks:

```bash
./attacker.sh 
```

## Components

### DDoS Monitor Application

A Tkinter-based GUI application that provides:
- Real-time visualization of network traffic
- Packet logging and analysis

### Attack Tracker

The detection engine that:
- Monitors packet rates (packets per second) - can be changed for single and mass ip attacks in the script
- Supports detection for single-source and distributed attacks
- Implements thresholds for normal vs. attack traffic

### Firewall Setup

Configures protective measures including:
- Rate limiting
- Connection tracking

## Testing Environment

- **Victim**: Metasploitable2 Linux virtual machine
- **Attackers**: Multiple Kali Linux virtual machines
- **Testing Network**: Isolated virtual network

## Contributors

- Varun Kukreti
- Vivek Arya

## Acknowledgements
- Department of Computer Science and Engineering, IIT Ropar

## Regulations

All tests are conducted in a controlled environment and for the purposes for simulation and testing. We in no way promote such activities. Simulating attacks on live servers and online websites is a cyber crime and legal offence and is punishable by law. 
