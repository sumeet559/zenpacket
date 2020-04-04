from scapy.all import IP,Raw

def rec_tcpip(packet):
    pkt = IP(packet.get_payload())
    print(pkt)
    if pkt.haslayer(Raw):
        load_contents = pkt[Raw].load
        print("RAW",load_contents)
    pkt.show2()
    return packet