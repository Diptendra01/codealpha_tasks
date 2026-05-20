from scapy.all import sniff, IP, TCP, UDP, ICMP

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

    print(f"\nPacket #{packet_count}")

    if packet.haslayer(IP):
        ip = packet[IP]
        print(f"Source IP      : {ip.src}")
        print(f"Destination IP : {ip.dst}")

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print("Protocol       : TCP")
            print(f"Source Port    : {tcp.sport}")
            print(f"Destination Port: {tcp.dport}")

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            print("Protocol       : UDP")
            print(f"Source Port    : {udp.sport}")
            print(f"Destination Port: {udp.dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

    else:
        print("Non-IP Packet")

    print("-" * 50)

sniff(prn=process_packet, count=20)