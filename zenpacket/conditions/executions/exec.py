from scapy.all import IP

def rec_tcpip(packet):
    pkt = IP(packet.get_payload())
    print("pkt",pkt)
    pkt.show2()
    packet.set_payload(bytes(pkt))
    return packet