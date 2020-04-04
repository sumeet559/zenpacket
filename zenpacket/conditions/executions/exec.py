from scapy.all import IP

def rec_tcpip(packet):
    print('H1')
    print('H11')
    pkt = IP(packets)
    print('H2')
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        print(pkt['TCP'].chksum)
        pkt.show2()
        return bytes(pkt)
    else:
        return None