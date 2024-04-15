import scapy.all as scapy

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.Raw):
            payload = packet[scapy.Raw].load
            print(f"[+] New Packet: {src_ip} -> {dst_ip} Protocol: {protocol} Payload: {payload}")
        else:
            print(f"[+] New Packet: {src_ip} -> {dst_ip} Protocol: {protocol}")

def main():
    print("[*] Starting packet sniffer...")
    scapy.sniff(iface="eth0", store=False, prn=packet_callback)

if __name__ == "__main__":
    main()
