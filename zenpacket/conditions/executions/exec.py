def rec_tcpip(packet):
    from scapy.all import IP
    pkt = IP(packet.get_payload())
    if pkt.haslayer('IP') and pkt.haslayer('TCP'):
        print(pkt['TCP'].chksum)
        pkt.show2()
        packet.set_payload(bytes(pkt))
        return packet
    else:
        return None