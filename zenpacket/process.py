from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
import pyscreenshot as ImageGrab
import cv2
import numpy as np 


def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    p = packet.get_payload()
    ppacket = IP(p)
    ppacket.show2()
    if ppacket.haslayer(HTTPRequest):
        url = ppacket[HTTPRequest].Host.decode() + ppacket[HTTPRequest].Path.decode()
        ip = ppacket[IP].src
        method = ppacket[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if ppacket.haslayer(Raw) and method == "POST":
            print(f"\n[*] Some useful Raw data: {ppacket[Raw].load}")
        if 'mail.google.com' in url:
            img_rgb = ImageGrab.grab()
            img_gray = cv2.cvtColor(img_rgb, cv2.COLOR_BGR2GRAY)
            template = cv2.imread('gmail.png',0)
            w, h = template.shape[::-1]
            res = cv2.matchTemplate(img_gray,template,cv2.TM_CCOEFF_NORMED) 
            threshold = 0.8
            loc = np.where( res >= threshold)  
            if loc[0].size > 0:
                return bytes(ppacket)
            else:
                return None
        else:
            return bytes(ppacket)
    return bytes(ppacket)
        
def process_sc_packet(ppacket):
    """
    This function is executed whenever a packet is sniffed
    """
    print(ppacket)
    if ppacket.haslayer(HTTPRequest):
        url = ppacket[HTTPRequest].Host.decode() + ppacket[HTTPRequest].Path.decode()
        ip = ppacket[IP].src
        method = ppacket[HTTPRequest].Method.decode()
        print(f"\n[+] {ip} Requested {url} with {method}")
        if ppacket.haslayer(Raw) and method == "POST":
            print(f"\n[*] Some useful Raw data: {ppacket[Raw].load}")
        if url == 'mail.google.com':
            img_rgb = ImageGrab.grab()
            img_gray = cv2.cvtColor(img_rgb, cv2.COLOR_BGR2GRAY)
            template = cv2.imread('gmail.png',0)
            w, h = template.shape[::-1]
            res = cv2.matchTemplate(img_gray,template,cv2.TM_CCOEFF_NORMED) 
            threshold = 0.8
            loc = np.where( res >= threshold)  
            if loc[0].size > 0:
                print("Allowed, proceed")
                return bytes(ppacket)
            else:
                print("Not Allowed, proceed")
                return None