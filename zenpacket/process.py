from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    p = packet.get_payload()
    ppacket = IP(p)
    if ppacket.haslayer(HTTPRequest):
        url = ppacket[HTTPRequest].Host.decode() + ppacket[HTTPRequest].Path.decode()
        ip = ppacket[IP].src
        method = ppacket[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if ppacket.haslayer(Raw) and method == "POST":
            print(f"\n[*] Some useful Raw data: {ppacket[Raw].load}")