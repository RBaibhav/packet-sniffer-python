# network-dashboard
🛡️ PacketCapture – A Python Network Packet Sniffer

This project implements a simple yet powerful packet capture tool using Scapy
.
It captures network packets in real time, extracts useful metadata (IP addresses, ports, protocol, size, and traffic type), and stores them in a thread-safe queue for processing.

📋 Features

-Real-time packet capturing using Scapy.
-Works in a background thread.
-Stores packets in a queue with configurable maximum size.
-Extracts details:
-Source & Destination IP
-Protocol (TCP/UDP/ICMP)
-Source & Destination Ports
-Traffic classification (HTTP, HTTPS, DNS, Email, File Transfer, Other)
-Packet size & timestamp
-Safely starts and stops capture.
-Handles queue overflow gracefully.

⚙️ Requirements

Python 3.8+

Scapy

Root/admin privileges to capture packets

🖥️ Setup with Virtual Environment

It’s recommended to use a Python virtual environment so dependencies don’t interfere with system packages.

1. Create and activate virtual environment
# Create venv
$python3 -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows PowerShell)
$venv\Scripts\Activate.ps1

2. Install dependencies
$pip install scapy

3. Run the script (with root/admin rights)
$sudo python3 packet_capture.py

🚀 Usage

When you run the script, it will:

Start packet capture in the background.

Capture for 10 seconds.

Print all captured packets.

Example Output:
Testing PacketCapture class...
packet capture started!
capturing packet for 10 seconds ....
Captured 42 packets
192.168.1.10 --> 142.250.183.78  [TCP]  HTTPS Packet Size [66]
192.168.1.10 --> 8.8.8.8  [UDP]  DNS Packet Size [74]
...
test Completed!

🛠️ Using the Class in Your Project
from packet_capture import PacketCapture
import time

capture = PacketCapture(max_queue_size=500)

capture.start_capture()
time.sleep(5)

packets = capture.get_all_packets()
for p in packets:
    print(p)

capture.stop_capturing()

⚠️ Notes

Run with sudo on Linux/Mac or as Administrator on Windows.

Queue size defaults to 1000; adjust if handling heavy traffic.

Captures metadata only (no full payload).

📌 Future Improvements

Save captured packets to .pcap or .json files.

Add filters (e.g., capture only TCP/UDP).

Real-time web dashboard for monitoring.