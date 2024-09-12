from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each packet
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine the protocol (TCP, UDP, ICMP, etc.)
        if proto == 6:  # TCP protocol
            protocol = "TCP"
        elif proto == 17:  # UDP protocol
            protocol = "UDP"
        elif proto == 1:  # ICMP protocol
            protocol = "ICMP"
        else:
            protocol = "Other"

        # Capture relevant information
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # Display payload (if available)
        if protocol == "TCP" and TCP in packet:
            print(f"Payload: {bytes(packet[TCP].payload)}")
        elif protocol == "UDP" and UDP in packet:
            print(f"Payload: {bytes(packet[UDP].payload)}")
        elif protocol == "ICMP" and ICMP in packet:
            print(f"Payload: {bytes(packet[ICMP].payload)}")
        print("-" * 50)


# Start sniffing
if __name__ == "__main__":
    print("Starting packet sniffer...")
    # sniff function captures the packets in real time
    sniff(filter="ip", prn=process_packet, store=False)
