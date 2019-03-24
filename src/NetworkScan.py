from tkinter import *
import sys
import socket
from datetime import datetime
from scapy.all import *
from netifaces import AF_INET
import netifaces as ni


class NetworkScan:
    def __init__(self, listbox):
        self.listbox = listbox

    @staticmethod
    def scan(listbox):
        ret = []
        try:
            f = open("/proc/net/if_inet6","r")
        except IOError and err:
            return ret
        l = f.readlines()
        for i in l:
            # addr, index, plen, scope, flags, ifname
            tmp = i.split()
            print(str(tmp[5]))
            ret.append(str(tmp[5]))
        for interface in ret:
            conf.iface = interface
            ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip+"/24"), timeout=10)

            for snd,rcv in ans:
                listbox.insert(END, rcv.sprintf(r"%Ether.src%        %ARP.psrc%"))
