import subprocess
import os
import sys
import importlib.util

def ensure_scapy():
    if not importlib.util.find_spec("scapy"):
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'scapy'])

def main():
    ensure_scapy()
    from scapy.all import sniff, DNS
    
    os.system('cls' if os.name == 'nt' else 'clear')
    
    def handler(pkt):
        if pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            domain = pkt[DNS].qd.qname.decode().rstrip('.')
            print(f"DNS Query: \033[94m{domain}\033[0m")

    try:
        sniff(filter="udp port 53", prn=handler, store=False)
    except KeyboardInterrupt:
        print("\n\033[93mExiting...\033[0m")

if __name__ == "__main__":
    main()
