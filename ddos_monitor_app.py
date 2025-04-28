#!/usr/bin/env python3
"""
DDoS Monitoring System
A traffic monitoring tool 
"""

import os
import time
import datetime
import threading
import argparse
from collections import defaultdict, deque
import subprocess
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk

class PacketMonitor:
    def __init__(self, interface, target_ip):
        self.interface = interface
        self.target_ip = target_ip
        
        
        # storage for packet data
        self.packet_logs = []
        self.packet_count_by_type = defaultdict(int)
        self.packet_count_by_source = defaultdict(int)
        
        
        # for real-time graphing
        self.timestamps = []
        self.packet_rates = []
        self.packet_types = defaultdict(list)
        
        # setup for the tcpdump command
        self.tcpdump_cmd = [
            'sudo', 'tcpdump', 
            '-i', self.interface, 
            f'host {self.target_ip}',
            '-n',   # not to  resolve hostnames
            '-e',   # use link-level header
            '-l',   # line-buffered output
            '-x'    # print packet data in hex
        ]

    def parse_packet(self, packet_data):
        # Parse raw packet data to extract information
        packet_info = {}
        try:
            parts = packet_data.split()
            if len(parts) < 5:
                return None
            packet_info['timestamp'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            
            for i, part in enumerate(parts):
                if part == '>':
                    if i > 0 and (i + 1) < len(parts):
                        src_str = parts[i - 1]
                        dst_str = parts[i + 1].rstrip(':')  # remove trailing colon
                        # extract the source IP (handle port if present)
                        src_parts = src_str.split('.')
                        if len(src_parts) >= 4:
                            src_ip = '.'.join(src_parts[:4])  # first four parts are IP
                        else:
                            src_ip = src_str  # fallback if no port
                        packet_info['source_ip'] = src_ip
                        # extracting the destination IP
                        dst_parts = dst_str.split('.')
                        if len(dst_parts) >= 4:
                            dst_ip = '.'.join(dst_parts[:4])
                        else:
                            dst_ip = dst_str
                        packet_info['dest_ip'] = dst_ip
                        # determine the protocol from subsequent parts
                        protocol = 'OTHERS'
                        for j in range(i + 2, len(parts)):
                            part_lower = parts[j].lower().rstrip(':')
                            if 'icmp' in part_lower:
                                protocol = 'ICMP'
                                break
                            elif 'tcp' in part_lower:
                                protocol = 'TCP'
                                # Check for SYN flag
                                if any('[S]' in p for p in parts[j:]):
                                    protocol = 'TCP SYN'
                                break
                            elif 'udp' in part_lower:
                                protocol = 'UDP'
                                break
                            elif 'http' in part_lower:
                                protocol = 'HTTP'
                                break
                            elif 'https' in part_lower:
                                protocol = 'HTTPS'
                                break
                            elif 'dns' in part_lower:
                                protocol = 'DNS'
                                break
                            elif 'ssh' in part_lower:
                                protocol = 'SSH'
                                break
                        packet_info['protocol'] = protocol
                        # extract packet size
                        for k, p in enumerate(parts):
                            if p == 'length':
                                try:
                                    packet_info['size'] = int(parts[k + 1].strip(':'))
                                except (ValueError, IndexError):
                                    packet_info['size'] = 0
                                break
                        break  # process first occurrence of '>' only
            return packet_info
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None

    def start_monitoring(self):
        # starting capturing and monitoring packets.
        try:

            process = subprocess.Popen(
                self.tcpdump_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            print(f"[+] Started monitoring on {self.interface} for traffic to/from {self.target_ip}")
            # output
            for line in process.stdout:
                if not line.strip():
                    continue
                packet_info = self.parse_packet(line)
                if packet_info:
                    self._process_packet(packet_info)
        except KeyboardInterrupt:
            print("\n[+] Stopping packet capture...")
        except Exception as e:
            print(f"[!] Error in monitoring: {e}")

    def _process_packet(self, packet_info):
       # process a parsed packet and update stats."""
    
        self.packet_logs.append(packet_info)
       
        if 'protocol' in packet_info:
            self.packet_count_by_type[packet_info['protocol']] += 1
        if 'source_ip' in packet_info:
            src_ip = packet_info['source_ip']
            self.packet_count_by_source[src_ip] += 1
     
        now = time.time()
        self.timestamps.append(now)
       
        cutoff = now - 300
        while self.timestamps and self.timestamps[0] < cutoff:
            self.timestamps.pop(0)
            if self.packet_rates:
                self.packet_rates.pop(0)
                
        # calculate the packet rate (packets per second)
        if len(self.timestamps) > 1:
            time_diff = self.timestamps[-1] - self.timestamps[0]
            if time_diff > 0:
                rate = len(self.timestamps) / time_diff
                self.packet_rates.append(rate)
            else:
                self.packet_rates.append(0)
        else:
            self.packet_rates.append(0)
       
        if 'protocol' in packet_info:
            protocol = packet_info['protocol']
            self.packet_types[protocol].append(now)
       
            while self.packet_types[protocol] and self.packet_types[protocol][0] < cutoff:
                self.packet_types[protocol].pop(0)

    def get_top_sources(self, limit=5):
        # Get the top packet sources by count
        sorted_sources = sorted(
            self.packet_count_by_source.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_sources[:limit]

    def get_packet_type_distribution(self):
        # Get distribution of packet types
        return dict(self.packet_count_by_type)

    def get_packet_logs(self, limit=100):
        # Get recent packet logs
        return self.packet_logs[-limit:]

class MonitoringApp:
    def __init__(self, root, monitor):
        self.root = root
        self.monitor = monitor
        self.root.title("DDoS Monitoring System")
        self.root.geometry("1000x800")
       # make tabs for different views
        self.tab_control = ttk.Notebook(root)
        # dashboard tab
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.dashboard_tab, text="Dashboard")
        # packet log tab
        self.logs_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.logs_tab, text="Packet Logs")
        self.tab_control.pack(expand=1, fill="both")
        # setup dashboard
        self.setup_dashboard()
        
        self.setup_logs_view()
        # start update loop
        self.update_data()

    def setup_dashboard(self):
        # Create the dashboard view with graphs
        
        left_frame = ttk.Frame(self.dashboard_tab)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right_frame = ttk.Frame(self.dashboard_tab)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        # traffic rate graph (top left)
        self.fig1 = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax1 = self.fig1.add_subplot(111)
        self.line1, = self.ax1.plot([], [], 'b-')
        self.ax1.set_title('Packet Rate (packets/second)')
        self.ax1.set_xlabel('Time (seconds)')
        self.ax1.set_ylabel('Packets/second')
        self.ax1.grid(True)
        canvas1 = FigureCanvasTkAgg(self.fig1, left_frame)
        canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # packet type distribution (top right)
        self.fig2 = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax2 = self.fig2.add_subplot(111)
        self.ax2.set_title('Packet Type Distribution')
        canvas2 = FigureCanvasTkAgg(self.fig2, right_frame)
        canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # top sources (bottom left)
        source_frame = ttk.LabelFrame(left_frame, text="Top Sources")
        source_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.source_tree = ttk.Treeview(source_frame, columns=('IP', 'Count'), show='headings')
        self.source_tree.heading('IP', text='Source IP')
        self.source_tree.heading('Count', text='Packet Count')
        self.source_tree.column('IP', width=150)
        self.source_tree.column('Count', width=100)
        self.source_tree.pack(fill=tk.BOTH, expand=True)
        # current stats (bottom right)
        stats_frame = ttk.LabelFrame(right_frame, text="Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # stats labels
        ttk.Label(stats_frame, text="Total Packets:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.total_packets_label = ttk.Label(stats_frame, text="0")
        self.total_packets_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, text="Packets/sec:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.packet_rate_label = ttk.Label(stats_frame, text="0")
        self.packet_rate_label.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, text="Target IP:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.target_ip_label = ttk.Label(stats_frame, text=self.monitor.target_ip)
        self.target_ip_label.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        ttk.Label(stats_frame, text="Interface:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.interface_label = ttk.Label(stats_frame, text=self.monitor.interface)
        self.interface_label.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

    def setup_logs_view(self):
        # Create the packet logs view
        frame = ttk.Frame(self.logs_tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    
        columns = ('Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Size')
        self.log_tree = ttk.Treeview(frame, columns=columns, show='headings')
        for col in columns:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=100)
        self.log_tree.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
    
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
   
        control_frame = ttk.Frame(self.logs_tab)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        ttk.Label(control_frame, text="Filter by protocol:").pack(side=tk.LEFT, padx=5)
        self.protocol_filter = ttk.Combobox(control_frame, values=['All', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'])
        self.protocol_filter.pack(side=tk.LEFT, padx=5)
        self.protocol_filter.current(0)
        ttk.Label(control_frame, text="Filter by IP:").pack(side=tk.LEFT, padx=5)
        self.ip_filter = ttk.Entry(control_frame, width=15)
        self.ip_filter.pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Apply Filters", command=self.update_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear Filters", command=self.clear_filters).pack(side=tk.LEFT, padx=5)

    def update_data(self):
        # ppdate all data displays
        self.update_dashboard_graphs()
        self.update_top_sources()
        self.update_stats()
        self.update_logs()

        self.root.after(1000, self.update_data)

    def update_dashboard_graphs(self):
        # Update the dashboard graphs
    
        timestamps = self.monitor.timestamps
        if timestamps:
            # find the relative time (seconds ago)
            now = time.time()
            rel_times = [t - now for t in timestamps]
            # get line graph
            self.line1.set_xdata(rel_times)
            self.line1.set_ydata(self.monitor.packet_rates)
            # adjust limits
            if rel_times:
                self.ax1.set_xlim(min(rel_times), max(rel_times) + 1)
            if self.monitor.packet_rates:
                max_rate = max(self.monitor.packet_rates) * 1.1
                self.ax1.set_ylim(0, max(1, max_rate))
            self.fig1.canvas.draw_idle()
        
        packet_types = self.monitor.get_packet_type_distribution()
        if packet_types:
            self.ax2.clear()
            self.ax2.set_title('Packet Type Distribution')
            labels = list(packet_types.keys())
            sizes = list(packet_types.values())
            # include non-zero values
            non_zero = [(l, s) for l, s in zip(labels, sizes) if s > 0]
            if non_zero:
                labels, sizes = zip(*non_zero)
                self.ax2.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
                self.ax2.axis('equal')
            self.fig2.canvas.draw_idle()

    def update_top_sources(self):
        # Update the top sources treeview
      
        for item in self.source_tree.get_children():
            self.source_tree.delete(item)
 
        top_sources = self.monitor.get_top_sources(10)
       
        for ip, count in top_sources:
            self.source_tree.insert('', tk.END, values=(ip, count))

    def update_stats(self):
        # Update the statistics labels
        total_packets = sum(self.monitor.packet_count_by_type.values())
        self.total_packets_label.config(text=str(total_packets))
      
        if self.monitor.packet_rates:
            current_rate = self.monitor.packet_rates[-1]
            self.packet_rate_label.config(text=f"{current_rate:.2f}")
        else:
            self.packet_rate_label.config(text="0")

    def update_logs(self):
        #  Update the packet logs view
    
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
      
        logs = self.monitor.get_packet_logs(1000)
      
        protocol_filter = self.protocol_filter.get()
        ip_filter = self.ip_filter.get().strip()
        filtered_logs = []
        for log in logs:
          
            if protocol_filter != 'All' and log.get('protocol') != protocol_filter:
                continue
        
            if ip_filter and ip_filter not in log.get('source_ip', '') and ip_filter not in log.get('dest_ip', ''):
                continue
            filtered_logs.append(log)
        # Display logs (most recent first)
        for log in reversed(filtered_logs[-100:]):  # Limit to 100 entries for performance
            values = (
                log.get('timestamp', ''),
                log.get('source_ip', ''),
                log.get('dest_ip', ''),
                log.get('protocol', ''),
                log.get('size', '')
            )
            self.log_tree.insert('', tk.END, values=values)

    def clear_filters(self):
        """Clear all filters in the logs view."""
        self.protocol_filter.current(0)
        self.ip_filter.delete(0, tk.END)
        self.update_logs()

def main():
    # parsing the command line arguments
    parser = argparse.ArgumentParser(description='DDoS Monitoring System')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('-t', '--target', required=True, help='Target IP to monitor')
    args = parser.parse_args()
    # needs to check if running as root
    if os.geteuid() != 0:
        print("[!] This program must be run as root to capture packets.")
        exit(1)
    # make a monitor in a separate thread
    monitor = PacketMonitor(interface=args.interface, target_ip=args.target)
    # starting the packet monitoring in a separate thread
    monitor_thread = threading.Thread(target=monitor.start_monitoring, daemon=True)
    monitor_thread.start()
    # starting the GUI
    root = tk.Tk()
    app = MonitoringApp(root, monitor)
    root.protocol("WM_DELETE_WINDOW", lambda: on_closing(root))
    root.mainloop()

def on_closing(root):
    """Clean up when closing the application."""
    print("[+] Cleaning up and exiting...")
    root.destroy()
    exit(0)

if __name__ == "__main__":
    import sys  # using sys for exit function
    main()
