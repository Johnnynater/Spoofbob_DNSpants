from scapy.all import *
from scapy.layers.l2 import *

# IP_REDIR:  The 'fake' IP Address of the spoofed domain
# IP_REAL:      The actual IP Address of the spoofed domain
# IP_VICTIM:    The IP Address of the victim
# IP_VM:        The IP Address of the virtual machine
# DOMAIN:       The domain to be spoofed


class DNS:
    def __init__(self, domain, ip_redirect):
        self.domain = domain
        self.ip_redirect = ip_redirect

    @staticmethod
    def spoof(domain, ip_redirect):
