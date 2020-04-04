from scapy.all import IP

def rec_tcpip(packet):
    pkt = IP(packet)
    print("SCAPPY",pkt)
    return bytes(pkt)