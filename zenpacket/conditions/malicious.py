from scapy.all import IP

def rec_tcpip(packet):
    pkt = IP(packet.get_payload())
    print(pkt)
    return packet