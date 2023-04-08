import subprocess

try:
    from scapy.all import *
except ImportError:
    subprocess.call(['pip', 'install', '-qy', 'scapy'])
    from scapy.all import *


def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        print(f"DNS Query Request: \033[94m{pkt.getlayer(DNS).qd.qname.decode().strip('.')}\033[m")


try:
    sniff(filter="udp port 53", prn=dns_sniffer)
except KeyboardInterrupt:
    print("Exiting...")
