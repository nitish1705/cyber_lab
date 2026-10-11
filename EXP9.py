# import time
# from scapy.all import sniff, ARP

# ip_map = {}

# def handle_arp(pkt):
#     if pkt.haslayer(ARP):
#         ip, mac, ts = pkt[ARP].psrc, pkt[ARP].hwsrc, time.time()
        
#         if ip not in ip_map:
#             ip_map[ip] = {"mac": mac, "first": ts, "last": ts, "count": 1}
#             print(f"[INFO] {time.ctime(ts)} Seen {ip} -> {mac}")

# print("[START] Sniffing... (Press Ctrl+C to stop)")
# try:
#     sniff(filter="arp", prn=handle_arp, store=False)
# except KeyboardInterrupt:
#     pass # Scapy usually catches this, but we put it here just in case
# finally:
#     # This block ALWAYS runs when the program exits
#     print("\n[STOP] Sniffing stopped.")
#     print("\n=== ARP WATCH SUMMARY ===")
#     for ip, info in ip_map.items():
#         print(ip_map)
#     print("=========================\n")


# Install: pip install scapy
import argparse, time
from scapy.all import sniff, ARP, rdpcap

ip_map = {}

def check(pkt):
    if ARP not in pkt:
        return
    ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc

    if ip in ip_map and ip_map[ip] != mac:
        print("ALERT: MAC changed for", ip, ip_map[ip], "->", mac)
    else:
        print("Seen:", ip, "->", mac)

    ip_map[ip] = mac

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--iface")
group.add_argument("--pcap")
args = parser.parse_args()

if args.pcap:
    for pkt in rdpcap(args.pcap):
        check(pkt)
else:
    try:
        sniff(iface=args.iface, filter="arp", prn=check, store=False)
    except KeyboardInterrupt:
        print("Stopped.")

