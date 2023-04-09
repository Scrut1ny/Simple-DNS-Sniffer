import subprocess
import os

# Clear the terminal
os.system('clear')

try:
    # Check if scapy is installed, if not install it silently
    from scapy.all import *
except ImportError:
    subprocess.call(['pip', 'install', '-qy', 'scapy'])
    from scapy.all import *


def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        # Print DNS query request in light blue and strip the trailing dot
        print(f"DNS Query Request: \033[94m{pkt.getlayer(DNS).qd.qname.decode().strip('.')}\033[m")


try:
    # Start sniffing on UDP port 53 for DNS traffic
    sniff(filter="udp port 53", prn=dns_sniffer)
except KeyboardInterrupt:
    # Exit gracefully if the user hits Ctrl+C
    print('\nExiting...')
