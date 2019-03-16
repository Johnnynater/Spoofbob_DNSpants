from src import DNS
from src import ARP
from tkinter import *
from tkinter import ttk


class Application(Tk):
    def __init__(self):
        super(Application, self).__init__()
        self.title("Window")
        self.minsize(640, 400)
        self.resizable(0, 0)

        tab_control = ttk.Notebook(self)

        self.tab1 = ttk.Frame(tab_control)      # About
        self.tab2 = ttk.Frame(tab_control)      # ARP Poisoning
        self.tab3 = ttk.Frame(tab_control)      # DNS Spoofing

        tab_control.add(self.tab1, text="About")
        tab_control.add(self.tab2, text="ARP Poisoning")
        tab_control.add(self.tab3, text="DNS Spoofing")

        tab_control.pack(expand=1, fill="both")

        """ ARP Poisoning tab interface """
        # Ethernet section
        eth = ttk.LabelFrame(self.tab2, text="Ethernet")
        eth.grid(column=0, row=0, padx=10, pady=10, ipadx=1, sticky=NW)

        ## Destination IP
        src = ttk.Label(eth, text="Destination IP address: ")
        src.grid(column=0, row=0, sticky=W)
        src_te = Entry(eth, width=20)
        src_te.grid(column=1, row=0)

        ## Source IP
        dst = ttk.Label(eth, text="Source IP address: ")
        dst.grid(column=0, row=1, pady=3, sticky=W,)
        dst_te = Entry(eth, width=20)
        dst_te.grid(column=1, row=1, pady=3)

        # ARP Section
        arp_header = ttk.LabelFrame(self.tab2, text="ARP")
        arp_header.grid(column=0, row=1, padx=10, pady=0, ipadx=1, sticky=NW)

        ## Sender MAC
        hwsrc = ttk.Label(arp_header, text="Sender MAC address:")
        hwsrc.grid(column=0, row=0, sticky=W)
        hwsrc_te = Entry(arp_header, width=20)
        hwsrc_te.grid(column=1, row=0)

        ## Sender IP
        psrc = ttk.Label(arp_header, text="Sender IP address: ")
        psrc.grid(column=0, row=1, sticky=W, pady=3)
        psrc_te = Entry(arp_header, width=20)
        psrc_te.grid(column=1, row=1, pady=3)

        ## Target MAC
        hwdst = ttk.Label(arp_header, text="Target MAC address:    ")
        hwdst.grid(column=0, row=2, sticky=W)
        hwdst_te = Entry(arp_header, width=20)
        hwdst_te.grid(column=1, row=2)

        ## Target IP
        pdst = ttk.Label(arp_header, text="Target IP address: ")
        pdst.grid(column=0, row=3, sticky=W, pady=3)
        pdst_te = Entry(arp_header, width=20)
        pdst_te.grid(column=1, row=3, pady=3)

        # Submit button
        sendpkt = ttk.Button(self.tab2, text="Send packet")
        sendpkt.grid(column=0, row=2)

        # Scan devices Section ARP
        label_scan = ttk.LabelFrame(self.tab2, text="Scan network")
        label_scan.grid(column=1, row=0, rowspan=4, padx=10, pady=10, ipadx=1, sticky=W)

        ## Scan network
        scan_network_txt = ttk.Label(label_scan, text="Scan the network connection to show all connected devices.")
        scan_network_txt.grid(column=0, row=0, columnspan=2, padx=2, sticky=W)

        self.scan_network_box = Listbox(label_scan, width=70)
        self.scan_network_box.grid(column=0, row=2, columnspan=2, padx=2, pady=3)

        scan_network_btn = ttk.Button(label_scan, width=20, text="Start network scan",
                                      command=self.start_scan)
        scan_network_btn.grid(column=0, row=1, padx=2, pady=5, sticky=W)

        set_target_btn = ttk.Button(label_scan, width=20, text="Set as target")
        set_target_btn.grid(column=0, row=3, padx=2, pady=5, sticky=W)

        set_all_btn = ttk.Button(label_scan, width=20, text="Attack all devices")
        set_all_btn.grid(column=1, row=3, pady=3, sticky=E)

        """ DNS Spoofing tab interface """
        # Spoofing Section
        spoof = ttk.LabelFrame(self.tab3, text="Domain and IP")
        spoof.grid(column=0, row=0, padx=10, pady=10, ipadx=1, sticky=W)

        ## Enter domain to be spoofed and send chosen IP to victim hosts
        domain_txt = ttk.Label(spoof, text="Domain to be spoofed: ")
        domain_txt.grid(column=0, row=0, sticky=W)

        domain_te = Entry(spoof, width=20)
        domain_te.grid(column=1, row=0)

        domain_txt_ex = ttk.Label(spoof, text="e.g. www.google.com ")
        domain_txt_ex.grid(column=1, row=1, sticky=W)

        ip_to_use_txt = ttk.Label(spoof, text="IP address to insert: ")
        ip_to_use_txt.grid(column=0, row=2, sticky=W)

        ip_to_use_te = Entry(spoof, width=20)
        ip_to_use_te.grid(column=1, row=2, pady=3, sticky=W)

        start_att_dns = ttk.Button(spoof, text="Start poisoning")
        start_att_dns.grid(column=0, row=3, columnspan=2)
        start_att_dns["command"] = self.start_dns(domain_te, ip_to_use_te)

    def start_scan(self):
            for item in ["one", "two", "three", "four", "one", "two", "three", "four"]:
                self.scan_network_box.insert(END, item)  # WRONG STILL

    @staticmethod
    def start_arp:
        ARP

    @staticmethod
    def start_dns(domain, ip):
        DNS.DNS.spoof(domain, ip)
        return 1


if __name__ == '__main__':
    app = Application()
    app.mainloop()
