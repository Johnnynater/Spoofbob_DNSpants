from tkinter import *
from scapy.all import *
from netifaces import AF_INET
import netifaces as ni


class NetworkScan:
    def __init__(self, listbox, scan_ip, scan_mac):
        self.listbox = listbox
        self.scan_ip = scan_ip
        self.scan_mac = scan_mac

    @staticmethod
    def scan(scan_ip, scan_mac, listbox):
        ret = []
        try:
            f = open("/proc/net/if_inet6","r")
        except IOError and err:
            return ret
        l = f.readlines()
        for i in l:
            # address, index, plen, scope, flags, ifname
            tmp = i.split()
            ret.append(str(tmp[5]))
        for interface in ret:
            conf.iface = interface
            ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip+"/24"), timeout=2)

            for snd,rcv in ans:
                scan_ip.append(rcv.sprintf(r"%ARP.psrc%"))
                scan_mac.append(rcv.sprintf(r"%Ether.src%"))
                listbox.insert(END, rcv.sprintf(r"%Ether.src%        %ARP.psrc%"))
