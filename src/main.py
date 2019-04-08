import DNS
import ARP
import NetworkScan
import threading
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import tkinter as tk


class Application(Tk):
    def __init__(self):
        # Set window title, size, and resizability
        super(Application, self).__init__()
        self.title("Spoofbob DNSpants")
        self.minsize(400, 480)
        self.resizable(0, 0)

        # Creates the tabs via a Notebook
        tab_control = ttk.Notebook(self)

        self.tab1 = ttk.Frame(tab_control)      # About
        self.tab2 = ttk.Frame(tab_control)      # ARP Poisoning
        self.tab3 = ttk.Frame(tab_control)      # DNS Spoofing

        tab_control.add(self.tab1, text="About")
        tab_control.add(self.tab2, text="ARP Poisoning")
        tab_control.add(self.tab3, text="DNS cache poisoning")

        tab_control.pack(expand=1, fill="both")

        # Set parameters used throughout
        self.scan_ip = []
        self.scan_mac = []
        self.target_ip = []
        self.target_mac = []
        self.domainlist = []

        self.bool_sniff = False
        self.bool_spoof_all = False

        """ About tab interface """
        big_title = ttk.Label(self.tab1, text="Spoofbob DNSpants", font=("Arial", 24, "bold"),
                             foreground="red", justify=tk.CENTER)
        big_title.grid(column=0, row=0, padx=10, pady=10)

        # About the creators of the tool
        intro = ttk.LabelFrame(self.tab1, text="Introduction")
        intro.grid(column=0, row=1, padx=10, pady=4, ipadx=1)

        intro_txt = ttk.Label(intro, wraplength=373,
                              text="Welcome to Spoofbob DNSpants! This tool provides the user the ability to perform"
                                   " ARP poisoning and DNS spoofing on targets within a Local Area Network. \n\n"
                                   "This tool was made for educational purposes only. The creators of this tool are "
                                   "not responsible for any criminal act that is done by the user. Use at own risk!")
        intro_txt.grid(column=0, row=0, columnspan=2, padx=4, pady=4, sticky=W)

        # About ARP
        about_arp = ttk.LabelFrame(self.tab1, text="ARP poisoning")
        about_arp.grid(column=0, row=2, padx=10, pady=4, ipadx=1)

        about_arp_txt = ttk.Label(about_arp, wraplength=368,
                                  text="Enables the user to see communication between two or more devices on the "
                                       "network. This is done by poisoning the ARP tables of each victim. "
                                       "The IP address of other victims in the table will contain your own MAC address,"
                                       " so all traffic will have to go to you first. \nSee README for "
                                       "a step-to-step instruction. ")

        about_arp_txt.grid(column=0, row=0, columnspan=2, padx=4, pady=4, sticky=W)

        # About DNS
        about_dns = ttk.LabelFrame(self.tab1, text="DNS cache poisoning")
        about_dns.grid(column=0, row=3, padx=10, pady=4, ipadx=1)

        about_dns_txt = ttk.Label(about_dns, wraplength=368,
                                  text="Enables the user to redirect victims on the network to the wrong website by "
                                       "DNS packet manipulation. This is done by ARP poisoning the Local DNS and "
                                       "Authoritative DNS and investigating their traffic. \n"
                                       "See README for a step-to-step instruction.")

        about_dns_txt.grid(column=0, row=0, columnspan=2, padx=4, pady=4, sticky=W)

        # About Creaters
        about_creators = ttk.LabelFrame(self.tab1, text="The creators")
        about_creators.grid(column=0, row=4, padx=10, pady=4, ipadx=1)

        about_creators_txt = ttk.Label(about_creators, wraplength=370,
                                       text="This tool was created by John van Lith and Isilsu Keles for "
                                            "the Lab Project assignment of the course Lab on Offensive Computer "
                                            "Security at Eindhoven University of Technology.")

        about_creators_txt.grid(column=0, row=0, columnspan=2, padx=4, pady=4, sticky=W)

        """ ARP Poisoning tab interface """
        # Scan devices Section ARP
        label_scan = ttk.LabelFrame(self.tab2, text="Scan network")
        label_scan.grid(column=0, row=0, columnspan=2, padx=14, pady=10, ipadx=1)

        ## Scan network
        scan_network_txt = ttk.Label(label_scan, text="Scan the network connection to show all connected devices.")
        scan_network_txt.grid(column=0, row=0, columnspan=2, padx=2, sticky=W)

        ## The listbox
        self.scan_network_box = Listbox(label_scan, width=51, height=12, selectmode='multiple', font=('Consolas', 9))
        self.scan_network_box.insert(0, "MAC:                     IP:                     ")
        self.scan_network_box.itemconfig(0, fg="gray")
        self.scan_network_box.grid(column=0, row=2, columnspan=3, padx=2, pady=3)

        ## Scan network button
        scan_network_btn = ttk.Button(label_scan, width=20, text="Start network scan",
                                      command=self.start_scan)
        scan_network_btn.grid(column=0, row=1, columnspan=2, padx=2, pady=5)

        ## Set selected as targets button
        set_target_btn = ttk.Button(label_scan, width=20, text="Use selected as target")
        set_target_btn.grid(column=0, row=3, padx=2, pady=6)
        set_target_btn["command"] = self.target_selected

        ## Set all as targets button
        set_all_btn = ttk.Button(label_scan, width=20, text="Target all")
        set_all_btn.grid(column=1, row=3, padx=2, pady=6)
        set_all_btn["command"] = self.target_all

        # FILL IN ADDITIONAL REQUIREMENTS
        additional_header = ttk.LabelFrame(self.tab2, text="Advanced settings (optional)")
        additional_header.grid(column=0, row=1, columnspan=3, padx=10, pady=10, ipadx=1)

        ## Attack frequency
        freq = ttk.Label(additional_header, text="Attack period:      ")
        freq.grid(column=0, row=0, padx=3, pady=5, sticky=W)
        self.freq_te = Entry(additional_header, width=12)
        self.freq_te.grid(column=1, row=0)
        freq_ex = tk.Label(additional_header, text="Default: 10 s          ", fg="gray", anchor=W)
        freq_ex.grid(column=2, row=0)

        ## Enable sniffing
        self.check_sniff = Checkbutton(additional_header, text="Sniff packets")
        self.check_sniff.grid(column=0, row=2, pady=3, sticky=W)
        self.check_sniff["variable"] = self.bool_sniff
        self.check_sniff["command"] = self.enable_sniff

        ## Packet amount to sniff
        self.pkt_cnt = ttk.Label(additional_header, text="Amount of packets:  ", state=DISABLED)
        self.pkt_cnt.grid(column=0, row=3, padx=3, pady=3, sticky=W)
        self.pkt_cnt_te = Entry(additional_header, width=12, state=DISABLED)
        self.pkt_cnt_te.grid(column=1, row=3, pady=5)
        self.pkt_ex = tk.Label(additional_header, text="  Default: 50 pkts       ",
                               fg="gray", justify=LEFT, state=DISABLED)
        self.pkt_ex.grid(column=2, row=3)

        # Start attack button
        self.start_att_arp = ttk.Button(self.tab2, text="Start attack", width=21)
        self.start_att_arp.grid(column=0, row=3, pady=13)
        self.start_att_arp["command"] = self.start_arp

        # Stop attack button
        self.stop_att_arp = ttk.Button(self.tab2, text="Stop attack", state=DISABLED, width=21)
        self.stop_att_arp.grid(column=1, row=3, pady=13)
        self.stop_att_arp["command"] = self.stop_arp

        """ DNS Spoofing tab interface """
        # Target domains Section ARP
        label_domain = ttk.LabelFrame(self.tab3, text="Target domains")
        label_domain.grid(column=0, row=0, columnspan=2, padx=14, pady=10, ipadx=1)

        ## Target text
        scan_network_txt = ttk.Label(label_domain, text=" Enter the domain(s) to be spoofed:"
                                                        "                                      ")
        scan_network_txt.grid(column=0, row=0, columnspan=4, padx=2, pady=2)

        ## Enter domain to be spoofed
        self.domain_te = Entry(label_domain, width=21)
        self.domain_te.grid(column=0, row=1, columnspan=3)
        self.domain_txt_ex = tk.Label(label_domain, text="e.g. www.google.com ", fg="gray", justify=tk.LEFT)
        self.domain_txt_ex.grid(column=3, row=1, sticky=W)

        ## Add target button
        self.add_domain_btn = ttk.Button(label_domain, width=20, text="Add target",
                                         command=self.add_domain)
        self.add_domain_btn.grid(column=1, row=2, padx=3, pady=6, sticky=W)

        ## Remove selected target button
        self.remove_domain_btn = ttk.Button(label_domain, width=20, text="Remove selected",
                                            command=self.del_domain)
        self.remove_domain_btn.grid(column=3, row=2, padx=2, pady=5)

        ## The listbox
        self.domain_box = Listbox(label_domain, width=51, height=11, font=('Consolas', 9))
        self.domain_box.insert(0, "Domain Name")
        self.domain_box.itemconfig(0, fg="gray")
        self.domain_box.grid(column=0, row=3, columnspan=4, padx=2, pady=3)

        ## Enable spoof all domain
        self.check_spoof = Checkbutton(label_domain, text="Spoof every incoming DNS packet")
        self.check_spoof.grid(column=0, row=4, columnspan=4, pady=3)
        self.check_spoof["variable"] = self.bool_spoof_all
        self.check_spoof["command"] = self.enable_spoof_all

        # Spoofing Section
        spoof = ttk.LabelFrame(self.tab3, text="IP Address configuration")
        spoof.grid(column=0, row=1, columnspan=2, padx=14, pady=10, ipadx=1, sticky=W)

        ## Enter IP of ns dns
        rec_dns_txt = ttk.Label(spoof, text="  Local DNS IP to poison: ")
        rec_dns_txt.grid(column=0, row=0, sticky=W)
        self.rec_dns_te = Entry(spoof, width=20)
        self.rec_dns_te.grid(column=1, row=0, pady=3, sticky=W)

        ## Enter IP of auth dns
        auth_dns_txt = ttk.Label(spoof, text="  Authoritative DNS IP:                ")
        auth_dns_txt.grid(column=0, row=1, sticky=W)
        self.auth_dns_te = Entry(spoof, width=20)
        self.auth_dns_te.grid(column=1, row=1, pady=3, sticky=W)
        blank = ttk.Label(spoof, text=" ")
        blank.grid(column=2, row=1)

        ## Enter IP to insert
        ip_to_use_txt = ttk.Label(spoof, text="  IP address to insert: ")
        ip_to_use_txt.grid(column=0, row=3, sticky=W)
        self.ip_to_use_te = Entry(spoof, width=20)
        self.ip_to_use_te.grid(column=1, row=3, pady=5, sticky=W)

        # Start Spoofing
        self.start_att_dns = ttk.Button(self.tab3, text="Start attack", width=21)
        self.start_att_dns.grid(column=0, row=2, pady=13)
        self.start_att_dns["command"] = self.start_dns

        # Stop Spoofing
        self.stop_att_dns = ttk.Button(self.tab3, text="Stop attack", width=21)
        self.stop_att_dns.grid(column=1, row=2, pady=13)
        self.stop_att_dns["command"] = self.stop_dns
        self.stop_att_dns["state"] = tk.DISABLED

    """" The functions that create dependencies between objects / classes """

    # Starts NetworkScan.py to scan the network for devices
    def start_scan(self):
        # Initialize parameters
        listbox = self.scan_network_box
        ns = NetworkScan.NetworkScan
        self.scan_network_box.delete(1, END)
        scan_ip = self.scan_ip
        scan_mac = self.scan_mac
        del scan_ip[:]
        del scan_mac[:]

        # Start network scan
        scan_thread = threading.Thread(target=ns.scan, args=(scan_ip, scan_mac, listbox,))
        scan_thread.start()
        scan_thread.join
        return

    # Targets selected devices in the listbox
    def target_selected(self):
        # Initialize parameters
        listbox = self.scan_network_box
        listbox.selection_clear(0)
        target_ip = self.target_ip
        target_mac = self.target_mac
        scan_ip = self.scan_ip
        scan_mac = self.scan_mac
        del target_ip[:]
        del target_mac[:]

        # Map all selected list entries and append them to two separate lists
        listitems = map(int, listbox.curselection())
        for x in listitems:
            target_ip.append(scan_ip[x - 1])
            target_mac.append(scan_mac[x - 1])
        print(self.target_ip)
        print(self.target_mac)

    # Targets all devices in the listbox
    def target_all(self):
        # Initialize parameters
        listbox = self.scan_network_box
        listbox.selection_clear(0)
        listbox.select_set(1, END)
        target_ip = self.target_ip
        target_mac = self.target_mac
        scan_ip = self.scan_ip
        scan_mac = self.scan_mac
        del target_ip[:]
        del target_mac[:]

        # Map all selected list entries and append them to two separate lists
        listitems = map(int, listbox.curselection())
        for x in listitems:
            target_ip.append(scan_ip[x - 1])
            target_mac.append(scan_mac[x - 1])
        print(self.target_ip)
        print(self.target_mac)

    # Adds domains from the entry box
    def add_domain(self):
        # Set parameters
        domain = self.domain_te.get()
        list = self.domain_box
        targets = self.domainlist

        if domain:
            targets.append(domain)
            list.insert(END, domain)
            print(domain + " was added")

    # Deletes selected domains
    def del_domain(self):
        # Set parameters
        list = self.domain_box
        list.selection_clear(0)
        targets = self.domainlist
        listitems = map(int, list.curselection())

        for x in listitems:
            del(targets[x - 1])
            print("Selection removed")
            list.delete(list.curselection())

    # Handles the boxes becoming writable/unwritable
    def enable_sniff(self):
        if not self.bool_sniff:
            self.pkt_cnt.config(state=NORMAL)
            self.pkt_cnt_te.config(state=NORMAL)
            self.pkt_ex.config(state=NORMAL)
            self.bool_sniff = True
        else:
            self.pkt_cnt.config(state=DISABLED)
            self.pkt_cnt_te.config(state=DISABLED)
            self.pkt_ex.config(state=DISABLED)
            self.bool_sniff = False

    # Handles the boxes becoming writable/unwritable
    def enable_spoof_all(self):
        if not self.bool_spoof_all:
            self.add_domain_btn.config(state=DISABLED)
            self.remove_domain_btn.config(state=DISABLED)
            self.domain_box.config(state=DISABLED)
            self.domain_te.config(state=DISABLED)
            self.domain_txt_ex.config(state=DISABLED)
            self.bool_spoof_all = True
        else:
            self.add_domain_btn.config(state=NORMAL)
            self.remove_domain_btn.config(state=NORMAL)
            self.domain_box.config(state=NORMAL)
            self.domain_te.config(state=NORMAL)
            self.domain_txt_ex.config(state=NORMAL)
            self.bool_spoof_all = False

    # Function that starts ARP poisoning
    def start_arp(self):
        # Initialize parameters
        target_ip = self.target_ip
        target_mac = self.target_mac
        freq = self.freq_te.get()
        pkt_cnt = self.pkt_cnt_te.get()
        bool_sniff = self.bool_sniff

        # Check for valid characters
        if len(target_ip) < 2:
            messagebox.showerror("Error", "Select at least two targets")
            return
        if freq:
            if not any(((c.isdigit()) for c in freq)):
                messagebox.showerror("Error", "Invalid input, only numbers are allowed for frequency and packet count.")
                return
        if pkt_cnt:
            if not any(((c.isdigit()) for c in pkt_cnt)):
                messagebox.showerror("Error", "Invalid input, only numbers are allowed for frequency and packet count.")
                return
        if not freq:
            freq = 10
        if not pkt_cnt:
            pkt_cnt = 50

        # Set boxes as active/inactive
        self.start_att_arp["state"] = tk.DISABLED
        self.stop_att_arp["state"] = tk.NORMAL

        # Start the attack
        for x in range(len(target_ip)):
            for y in range(x+1, len(target_ip)):
                if y != x:
                    attack_thread = threading.Thread(target=ARP.ARPattack.start_attack, args=(target_ip[x], target_mac[x], target_ip[y], target_mac[y], freq, pkt_cnt, bool_sniff))
                    attack_thread.start()
        return

    # Function that stops ARP poisoning
    def stop_arp(self):
        # Initialize parameters
        # Set boxes as active/inactive
        self.start_att_arp["state"] = tk.NORMAL
        self.stop_att_arp["state"] = tk.DISABLED
        target_ip = self.target_ip

        # Stop the attack
        for x in range(len(target_ip)):
            for y in range(x+1, len(target_ip)):
                if x != y:
                    ARP.ARPattack.loop_bool = False
        return

    # Function that starts DNS cache poisoning
    def start_dns(self):
        # Initialize parameters
        chars_ip = set('0123456789.')
        dns = DNS.DNSattack
        domain = self.domainlist
        ip = self.ip_to_use_te.get()
        auth = self.auth_dns_te.get()
        rec = self.rec_dns_te.get()
        spoof_all = self.bool_spoof_all

        # Check for valid characters
        if not domain and not spoof_all:
            messagebox.showerror("Error", "Please select a domain to spoof or check the spoof all box")
            return
        if not any(((c in chars_ip) for c in ip)):
            messagebox.showerror("Error", "Invalid input, only numbers and dots are allowed for IP Addresses.")
            return
        if not any(((c in chars_ip) for c in auth)):
            messagebox.showerror("Error", "Invalid input, only numbers and dots are allowed for IP Addresses.")
            return
        if not any(((c in chars_ip) for c in auth)):
            messagebox.showerror("Error", "Invalid input, only numbers and dots are allowed for IP Addresses.")
            return

        # Set boxes as active/inactive
        self.start_att_dns["state"] = tk.DISABLED
        self.stop_att_dns["state"] = tk.NORMAL

        # Start the attack
        if spoof_all:
            spoof_all_thread = threading.Thread(target=dns.start_spoof_all, args=(ip, auth, rec))
            spoof_all_thread.start()
        else:
            for x in range(len(domain)):
                spoof_thread = threading.Thread(target=dns.start_spoof, args=(domain[x], ip, auth, rec))
                spoof_thread.start()
        return

    # Function that stops DNS cache poisoning
    def stop_dns(self):
        # Set parameters
        # Set boxes as active/inactive
        domain = self.domainlist
        self.start_att_dns["state"] = tk.NORMAL
        self.stop_att_dns["state"] = tk.DISABLED

        # Stop the attack
        for x in range(len(domain)):
            ARP.ARPattack.loop_bool = False
            DNS.DNSattack.exit_loop = True


if __name__ == '__main__':
    app = Application()
    app.mainloop()
