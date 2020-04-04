from scapy.all import IP

def rec_tcpip(packet):
    print('H1')
    print('H11')
    pkt = IP(packet.get_payload())
    print('H2')
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        print(pkt['TCP'].chksum)
        pkt.show2()
        packet.set_payload(bytes(pkt))
        return packet
    else:
        return None