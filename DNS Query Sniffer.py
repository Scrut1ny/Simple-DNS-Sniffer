import subprocess
import os
from scapy.all import *

# Clear the terminal
os.system('cls' if os.name == 'nt' else 'clear')

# Ensure Scapy is installed
def ensure_scapy_installed():
    try:
        from scapy.all import *
    except ImportError:
        subprocess.call(['pip', 'install', '-qy', 'scapy'])
        from scapy.all import *

# Function to handle DNS packets
def dns_sniffer(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
        query_name = pkt.getlayer(DNS).qd.qname.decode().strip('.')
        print(f"DNS Query Request: \033[94m{query_name}\033[m")

def main():
    ensure_scapy_installed()
    try:
        # Start sniffing on UDP port 53 for DNS traffic
        sniff(filter="udp port 53", prn=dns_sniffer)
    except KeyboardInterrupt:
        print('\nExiting...')

if __name__ == "__main__":
    main()
