from scapy.all import *
from scapy.layers.l2 import *

# IP_REDIR:  The 'fake' IP Address of the spoofed domain
# IP_REAL:      The actual IP Address of the spoofed domain
# IP_VICTIM:    The IP Address of the victim
# IP_VM:        The IP Address of the virtual machine
# DOMAIN:       The domain to be spoofed


class ARP:
    def __init__(self, src, dst, hwsrc, psrc, hwdst, pdst):
        self.src = src
        self.dst = dst
        self.hwsrc = hwsrc
        self.psrc = psrc
        self.hwdst = hwdst
        self.pdst = pdst

    @staticmethod
    def spoof(src, dst, hwsrc, psrc, hwdst, pdst):
        print("sicko mate gj")
        print("easy peasy")

"""
from tkinter import *


class Application(Frame):


    def __init__(self, master):

        Frame.__init__(self, master)
        self.grid()
        self.button_clicks = 0
        self.create_widgets()

    def create_widgets(self):

        # Create a label
        self.instruction = Label(self)
        self.instruction["text"] = "Enter your IP Address"
        self.instruction.grid(row=0, column=0, columnspan=2, sticky=W)

        # Create an entry
        self.pswd = Entry(self)
        self.pswd.grid(row=1, column=1, sticky=W)

        # Create a submit button
        self.submit_button = Button(self)
        self.submit_button["text"] = "Submit"
        self.submit_button["command"] = self.reveal
        self.submit_button.grid(row=2, column=0, sticky=W)

        # Create text
        self.text = Text(self, state=DISABLED, width=35, height=5, wrap=WORD)
        self.text.grid(row=3, column=0, columnspan=2, sticky=W)

        # Create a counter button
        self.button = Button(self)
        self.button["text"] = "Total clicks: 0"
        self.button["command"] = self.update_counter
        self.button.grid()

        # Create a button that goes to another GUI
        self.newtab = Button(self)
        self.newtab["text"] = "Go to another page"
        self.newtab["command"] = self.goto_new_window
        self.newtab.grid()

    def update_counter(self):

        self.button_clicks += 1
        self.button["text"] = "Total clicks: " + str(self.button_clicks)

    def reveal(self):

        content = self.pswd.get()

        if (content == "password"):
            message = "Good job fam"

        else:
            message = "Access denied"
        self.text["state"] = NORMAL
        self.text.delete(0.0, END)
        self.text.insert(0.0, message)
        self.text["state"] = DISABLED

    def goto_new_window(self):
        newpage.mainloop()


root = Tk()
root.title("Three buttons")
root.geometry("300x300")

newpage = Tk()
newpage.title("New page")
newpage.geometry("300x300")

app = Application(root)

root.mainloop()
"""