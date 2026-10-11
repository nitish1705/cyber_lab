from scapy.all import *
from collections import Counter

arp, ports, syn = {}, {}, Counter()

def check(p):
    if ARP in p:
        ip, mac = p[ARP].psrc, p[ARP].hwsrc
        if ip in arp and arp[ip] != mac:
            print("ARP Conflict:", ip)
        arp[ip] = mac

    if IP in p and TCP in p:
        ip, port = p[IP].src, p[TCP].dport
        ports.setdefault(ip, set()).add(port)
        if len(ports[ip]) > 5:
            print("Port Scan:", ip)
            ports[ip].clear()
        if p[TCP].flags == "S":
            syn[ip, port] += 1
            if syn[ip, port] > 10:
                print("SYN Flood:", ip)
                syn[ip, port] = 0

sniff(filter="arp or tcp", prn=check, store=False)