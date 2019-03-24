import DNS
import ARP
import NetworkScan
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import tkinter as tk


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
        # FILL IN GATEWAY AND TARGET
        eth = ttk.LabelFrame(self.tab2, text="Gateway and Target")
        eth.grid(column=0, row=0, padx=10, pady=10, ipadx=1, sticky=NW)

        ## Gateway IP
        g_ip = ttk.Label(eth, text="Gateway IP: ")
        g_ip.grid(column=0, row=0, sticky=W)
        self.g_ip_te = Entry(eth, width=20)
        self.g_ip_te.grid(column=1, row=0)

        ## Gateway MAC
        g_mac = ttk.Label(eth, text="Gateway MAC: ")
        g_mac.grid(column=0, row=1, pady=3, sticky=W,)
        self.g_mac_te = Entry(eth, width=20)
        self.g_mac_te.grid(column=1, row=1, pady=3)

        ## Target IP
        t_ip = ttk.Label(eth, text="Target IP: ")
        t_ip.grid(column=0, row=2, sticky=W)
        self.t_ip_te = Entry(eth, width=20)
        self.t_ip_te.grid(column=1, row=2)

        ## Target MAC
        t_mac = ttk.Label(eth, text="Target MAC: ")
        t_mac.grid(column=0, row=3, sticky=W, pady=3)
        self.t_mac_te = Entry(eth, width=20)
        self.t_mac_te.grid(column=1, row=3, pady=3)

        # FILL IN ADDITIONAL REQUIREMENTS
        arp_header = ttk.LabelFrame(self.tab2, text="Advanced settings")
        arp_header.grid(column=0, row=1, padx=10, pady=0, ipadx=1, sticky=NW)

        ## Attack frequency
        freq = ttk.Label(arp_header, text="Attack frequency: ")
        freq.grid(column=0, row=0, sticky=W)
        self.freq_te = Entry(arp_header, width=10)
        self.freq_te.grid(column=1, row=0)
        freq_ex = tk.Label(arp_header, text="default: 10 s", fg="gray", justify=tk.LEFT)
        freq_ex.grid(column=1, row=1)

        ## Target IP
        pkt_cnt = ttk.Label(arp_header, text="Amount of packets: ")
        pkt_cnt.grid(column=0, row=2, sticky=W, pady=3)
        self.pkt_cnt_te = Entry(arp_header, width=10)
        self.pkt_cnt_te.grid(column=1, row=2, pady=3)
        pkt_ex = tk.Label(arp_header, text="default: 1000", fg="gray", justify=tk.LEFT)
        pkt_ex.grid(column=1, row=3)

        # Submit button
        start_att_arp = ttk.Button(self.tab2, text="Start attack")
        start_att_arp.grid(column=0, row=2)
        start_att_arp["command"] = self.start_arp

        # Scan devices Section ARP
        label_scan = ttk.LabelFrame(self.tab2, text="Scan network")
        label_scan.grid(column=1, row=0, rowspan=4, padx=10, pady=10, ipadx=1, sticky=W)

        ## Scan network
        scan_network_txt = ttk.Label(label_scan, text="Scan the network connection to show all connected devices.")
        scan_network_txt.grid(column=0, row=0, columnspan=2, padx=2, sticky=W)

        self.scan_network_box = Listbox(label_scan, width=50, font=('Consolas', 9))
        self.scan_network_box.insert(0, "MAC:                     IP:                          ")
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

        self.domain_te = Entry(spoof, width=20)
        self.domain_te.grid(column=1, row=0)

        domain_txt_ex = tk.Label(spoof, text="e.g. www.google.com ", fg="gray", justify=tk.LEFT)
        domain_txt_ex.grid(column=1, row=1, sticky=W)

        ip_to_use_txt = ttk.Label(spoof, text="IP address to insert: ")
        ip_to_use_txt.grid(column=0, row=2, sticky=W)

        self.ip_to_use_te = Entry(spoof, width=20)
        self.ip_to_use_te.grid(column=1, row=2, pady=3, sticky=W)

        start_att_dns = ttk.Button(spoof, text="Start poisoning")
        start_att_dns.grid(column=0, row=3, columnspan=2)
        start_att_dns["command"] = self.start_dns

    def start_scan(self):
        listbox = self.scan_network_box
        ns = NetworkScan.NetworkScan
        self.scan_network_box.delete(1, END)

        ns.scan(listbox)

        return

    def start_arp(self):
        # Initialize parameters
        chars_ip = set('0123456789.')
        chars_mac = set('0123456789abcdef:')
        g_ip = self.g_ip_te.get() #"192.168.56.102"
        g_mac = self.g_mac_te.get() #"08:00:27:a5:77:05"
        t_ip = self.t_ip_te.get() #"192.168.56.101"
        t_mac = self.t_mac_te.get() #"08:00:27:52:4c:a4"
        freq = self.freq_te.get()
        pkt_cnt = self.pkt_cnt_te.get()

        # Check for valid characters
        if not(g_ip or g_mac or t_ip or t_mac):
            messagebox.showerror("Error", "Not every required field is filled in.")
            return
        if not any(((c in chars_ip) for c in g_ip and t_ip)):
            messagebox.showerror("Error", "Invalid input, only numbers and dots are allowed for IP Addresses.")
            return
        if not any(((c in chars_mac) for c in g_mac and t_mac)):
            messagebox.showerror("Error", "Invalid input, only hexadecimal values and : are allowed for MAC Addresses.")
            return
        if not any(((c.isdigit()) for c in freq and pkt_cnt)):
            messagebox.showerror("Error", "Invalid input, only numbers are allowed for frequency and packet count.")
            return
        if not freq:
            freq = 10
        if not pkt_cnt:
            pkt_cnt = 1000

        # Start the attack
        ARP.ARPattack.start_attack(g_ip, g_mac, t_ip, t_mac, freq, pkt_cnt)

        return

    def start_dns(self):
        # Initialize parameters
        chars_ip = set('0123456789.')
        dns = DNS.DNS
        domain = self.domain_te.get()
        ip = self.ip_to_use_te.get()

        # Check for valid characters
        if not(domain and ip):
            messagebox.showerror("Error", "Not every required field is filled in.")
            return
        if not any(((c in chars_ip) for c in ip)):
            messagebox.showerror("Error", "Invalid input, only numbers and dots are allowed for IP Addresses.")
            return

        # Start the attack
        dns.spoof(domain, ip)

        return


if __name__ == '__main__':
    app = Application()
    app.mainloop()
