from scapy.all import IP

def rec_tcpip(packet):
    pkt = IP(packet)
    print('H2')
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        print(pkt['TCP'].chksum)
        pkt.show2()
        return bytes(pkt)
    else:
        return None