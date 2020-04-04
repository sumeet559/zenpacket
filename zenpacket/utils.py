from scapy.all import *

def parse_packet(packet):
    return IP(packet)

def raw_packet(packet):
    return bytes(packet)