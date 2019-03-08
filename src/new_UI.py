from tkinter import *
from tkinter import ttk


class Application(Tk):
    def __init__(self):
        super(Application, self).__init__()
        self.title("Window")
        self.minsize(640, 400)
        self.resizable(0, 0)

        tab_control = ttk.Notebook(self)

        self.tab1 = ttk.Frame(tab_control)
        self.tab2 = ttk.Frame(tab_control)
        self.tab3 = ttk.Frame(tab_control)

        tab_control.add(self.tab1, text="About")
        tab_control.add(self.tab2, text="ARP Poisoning")
        tab_control.add(self.tab3, text="DNS Spoofing")

        tab_control.pack(expand=1, fill="both")

        self.create_widgets()

    def create_widgets(self):
        # Ethernet section
        eth = ttk.LabelFrame(self.tab2, text="Ethernet")
        eth.grid(column=0, row=0, padx=10, pady=10, ipadx=1, sticky=W)

        ## Destination IP
        src = ttk.Label(eth, text="Destination IP address: ")
        src.grid(column=0, row=0, sticky=W)
        src_te = Entry(eth, width=20)
        src_te.grid(column=1, row=0)

        ## Source IP
        dst = ttk.Label(eth, text="Source IP address: ")
        dst.grid(column=0, row=1, sticky=W, pady=3)
        dst_te = Entry(eth, width=20)
        dst_te.grid(column=1, row=1, pady=3)

        # ARP Section
        arp_header = ttk.LabelFrame(self.tab2, text="ARP")
        arp_header.grid(column=0, row=1, padx=10, pady=0, ipadx=1, sticky=W)

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


if __name__ == '__main__':
    app = Application()
    app.mainloop()
