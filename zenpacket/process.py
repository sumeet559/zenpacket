from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    packet = IP(packet)
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if packet.haslayer(Raw) and method == "POST":
            print(f"\n[*] Some useful Raw data: {packet[Raw].load}")