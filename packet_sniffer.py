from scapy.all import sniff, IP, TCP, UDP, Raw

# Function to process each captured packet
def packet_callback(packet):
    # Display packet summary
    print(packet.summary())
    
    # If the packet has an IP layer, print detailed information
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        
        # Handling different protocol types (TCP, UDP, ICMP)
        if packet.haslayer(TCP):
            print("Protocol Type: TCP")
        elif packet.haslayer(UDP):
            print("Protocol Type: UDP")
        elif packet.haslayer(ICMP):
            print("Protocol Type: ICMP")
        
        # Display payload data if available
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                # Try to decode the payload if it's a text-based protocol
                decoded_payload = payload.decode("utf-8", errors="ignore")
                print(f"Payload Data: {decoded_payload}")
            except:
                print(f"Payload Data: {payload}")
        print('-' * 50)

# Start sniffing the network
def start_sniffing(interface=None):
    print("Starting packet sniffing...")
    sniff(iface=interface, prn=packet_callback, store=0)  # interface can be None for default interface

# Run the packet sniffer
if __name__ == "__main__":
    interface = input("Enter network interface to sniff on (or press Enter for default): ")
    start_sniffing(interface if interface else None)
