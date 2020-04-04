from scapy.all import IP

def rec_tcpip(packet):
    pkt = IP(packet)
    print(pkt)
    return bytes(pkt)