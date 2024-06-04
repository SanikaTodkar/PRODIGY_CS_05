import scapy.all as scapy

def sniff_packets(interface, count):
    scapy.sniff(iface=interface, count=count, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")

    if packet.haslayer(scapy.TCP):
        tcp_sport = packet[scapy.TCP].sport
        tcp_dport = packet[scapy.TCP].dport
        print(f"TCP Source Port: {tcp_sport}, TCP Destination Port: {tcp_dport}")

    if packet.haslayer(scapy.UDP):
        udp_sport = packet[scapy.UDP].sport
        udp_dport = packet[scapy.UDP].dport
        print(f"UDP Source Port: {udp_sport}, UDP Destination Port: {udp_dport}")

    if packet.haslayer(scapy.ICMP):
        icmp_type = packet[scapy.ICMP].type
        icmp_code = packet[scapy.ICMP].code
        print(f"ICMP Type: {icmp_type}, ICMP Code: {icmp_code}")

    if packet.haslayer(scapy.Raw):
        payload = packet[scapy.Raw].load
        print(f"Payload: {payload}")

    print("")

def main():
    interface = input("Enter the interface to sniff (e.g. eth0, wlan0): ")
    count = int(input("Enter the number of packets to capture: "))
    sniff_packets(interface, count)

if __name__ == "__main__":
    main()