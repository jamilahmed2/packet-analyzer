# Ethical Use Disclaimer
This tool is intended for educational purposes only. It is designed to demonstrate basic packet sniffing and network traffic analysis in a controlled, ethical environment.

Authorized Usage: You should only use this tool on networks where you have explicit permission to monitor traffic. Examples include your own network or a controlled lab environment.
Unauthorized Use: Unauthorized interception or analysis of network traffic without the consent of all parties involved is illegal and unethical. Do not use this tool on any network without permission.
Respect Privacy: This tool should never be used to collect or exploit sensitive personal information. Always act responsibly and respect privacy laws.
Liability: The creators of this project do not condone or promote the malicious use of this tool. By using this software, you agree to comply with legal and ethical standards.
Use this tool at your own risk. We do not take responsibility for any misuse of the software or any legal consequences that may arise.



# Usage Instructions
A simple Python-based packet sniffer built with Scapy that captures and analyzes network packets. It extracts detailed information like source and destination IPs, protocols (TCP, UDP, ICMP), and payload data.

# Features
Captures and displays packet summaries.
Extracts detailed information for packets with IP layers.
Identifies protocol types (TCP, UDP, ICMP).
Displays raw payload data and attempts to decode it for text-based protocols.
Easy-to-use interface for selecting the network interface.

# Prerequisites
Python: Ensure Python 3.8+ is installed. Download Python
Scapy: Install the Scapy library:


pip install scapy
Npcap (Windows) or libpcap (Linux/Mac): https://npcap.com/dist/npcap-1.80.exe
Windows: Install Npcap. Ensure "WinPcap API-compatible mode" is selected during installation.
Linux/Mac: Install libpcap using your package manager:

sudo apt install libpcap-dev  # Ubuntu/Debian
brew install libpcap          # macOS
Usage
Clone the repository:



git clone https://github.com/jamilahmed2/packet-analyzer.git
cd packet-analyzer
Run the script with administrative privileges:

Windows:


python packet_sniffer.py
Linux/Mac:


sudo python packet_sniffer.py
Enter the network interface to sniff on (e.g., eth0, wlan0, or leave blank for the default interface).

Watch captured packets in real-time, along with detailed analysis.