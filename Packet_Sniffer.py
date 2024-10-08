#do pip install scapy

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import logging

logging.basicConfig(filename="sniffer_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = "Unknown"

        if packet.haslayer(TCP):
            protocol = "TCP"
            tcp_layer = packet[TCP]
            print(f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
            logging.info(f"[TCP] {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")

        elif packet.haslayer(UDP):
            protocol = "UDP"
            udp_layer = packet[UDP]
            print(f"[UDP] {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")
            logging.info(f"[UDP] {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")

        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            print(f"[ICMP] {ip_layer.src} -> {ip_layer.dst}")
            logging.info(f"[ICMP] {ip_layer.src} -> {ip_layer.dst}")

        else:
            print(f"[{protocol}] {ip_layer.src} -> {ip_layer.dst}")
            logging.info(f"[{protocol}] {ip_layer.src} -> {ip_layer.dst}")

# Sniffer function
def start_sniffing(filter_protocol=None):
    if filter_protocol:
        # Filter packets based on the provided protocol
        sniff(filter=filter_protocol, prn=process_packet)
    else:
        # Sniff without any filter
        sniff(prn=process_packet)

if __name__ == "__main__":
    print("Starting network packet sniffer...")
    protocol = input("Enter protocol to filter (tcp/udp/icmp) or leave empty for all: ").lower()

    if protocol in ["tcp", "udp", "icmp"]:
        filter_protocol = protocol
        start_sniffing(filter_protocol)
    else:
        start_sniffing()

