# Spoofbob DNSpants
Spoofbob DNSpants is a tool that is able to perform ARP poisoning and DNS cache poisoning within a Local Area Network.
Development and testing was done inside a Linux VM using VirtualBox. ARP poisoning was performed on a victim
VM with Windows XP and another victim VM with Debian 9. DNS cache poisoning was performed on the Linux VM, with
two victim DNS servers; a recursive DNS server and an authoritative DNS server, both of them being Debian 9 VMs.

This tool was made by John van Lith and Isilsu Keles as a Lab project for the course 2IC80 - Lab on Offensive Computer Security
at Eindhoven University of Technology. Misusing this tool for illegal purposes is at own risk, we are not responsible.

---

Software required for the application to work and how to install:

- Scapy v2.4.2
    1. Inside your Linux terminal, enter "sudo pip install scapy"
- Netifaces
    1. Inside your Linux terminal, enter "sudo pip install netifaces"
    
How to run the application:

1. Go to the /src file and open your terminal
2. Enter "sudo python3 main.py" to start the application

---

How to perform ARP poisoning:

1. Go to the tab "ARP poisoning"
2. Scan the Local Area Network by pressing the "Start network scan" button
3. After the scan is done, select at least two targets to poison and confirm by pressing "Use selected as target"
    - Alternatively, press "Target all" to target all scanned devices
4. Set the attack period (interval of resending ARP poisoning packets) or leave it blank for a default period
5. Enable packet sniffing or leave it unchecked
    - If enabled, set the amount of packets to sniff or leave it blank for a default amount
6. Press "Start attack"
7. Once you are done attacking, press "Stop attack". This will restore the ARP tables of each victim

---

How to perform DNS cache poisoning:

1. Go to the tab "DNS cache poisoning"
2. Enter the domains to spoof inside the entry box, press "Add target" to confirm
    - If a mistake was made, select the domain in the list and press "Remove selected"
    - Alternatively, activate "Spoof every incoming DNS packet" to target all domains
3. Set the IP addresses of the local DNS (recursive DNS), authoritative DNS, and the IP to inject in the DNS packets
4. Press "Start attack"
5. Open your web browser and enter the targeted domain
    - If the local DNS already cached the IP address of the domain before the attack, the poisoning failed
    - If the local DNS did not have the IP address of the domain cached, success!
6. Once you are done attacking, press "Stop attack". Poisoned cache entries will remain poisoned until the DNS is flushed
