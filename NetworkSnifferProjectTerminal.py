# This program allows the user to Sniff, ARP Ping and Traceroute using scapy

# Expected Initial Output of the program:
# Are you ready to have some fun? [y/n]
# Awesome! Do you want to:
# 1) Sniff
# 2) ARP Ping
# 3) Traceroute

# Importing scapy and others

from scapy.all import *
from colorama import Fore
# Standard step in scapy, to supress the scapy IPV6 warning
import logging
from scapy.layers.inet import traceroute, arping
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# FN to specify user selection
def choice_options():
    print("Awesome! Do you want to: ")
    print("1) Sniff ")
    print("2) ARP Ping")
    print("3) Traceroute")
    print("4) Quit")
    user_choice=int(input("Input 1/2/3/4:"))
    if user_choice == 1:
        sniffer_core()
    elif user_choice==2:
        arp_core()
    elif user_choice==3:
        traceroute_core()
    elif user_choice==4:
        print("Goodbye!")
        quit()

# FN to specify interface
def getInterface():
        interface=""
        print("Choose the interface to sniff:")
        print("1) Any")
        print("2) wlan0")
        print("3) eth0")
        print("4) lo ")
        user_input = int(input("Enter Selection 1/2/3/4: "))
        if user_input ==1:
            interface="any"
        elif  user_input ==2:
            interface="wlan0"
        elif user_input == 3:
            interface="eth0"
        elif user_input == 4:
            interface="lo"
        return interface

# FN to specify filter
def getFilter():
    filter = ""
    print("Choose the desired filter:")
    print("1) None")
    print("2) IP")
    print("3) TCP")
    print("4) UDP")
    print("5) ICMP")
    print("6) Other ")
    user_input = int(input("Enter Selection 1/2/3/4/5/6: "))
    if user_input == 1:
        filter = "none"
    elif user_input == 2:
        filter = "ip"
    elif user_input == 3:
        filter = "tcp"
    elif user_input == 4:
        filter = "udp"
    elif user_input == 5:
        filter = "icmp"
    elif user_input == 6:
        filter = input("Input desired filter: ")
    return filter

# FN to specify packet count
def  getCount():
    num=-1
    print("Choose Number of Packets to Sniff:")
    print("1) Default [20 Packets]")
    print("2) User Defined ")
    user_input = int(input("Enter Selection 1/2/: "))
    if user_input == 1:
        num = -1
    elif user_input == 2:
        num = int(input("Enter Number of Packets: "))
    return num

# FN to specify timeout
def  getTimeout():
    num=-1
    print("Choose Timeout Period:")
    print("1) Default [30]")
    print("2) User Defined ")
    user_input = int(input("Enter Selection 1/2/: "))
    if user_input == 1:
        num = -1
    elif user_input == 2:
        num = int(input("Enter Timeout Period: "))
    return num

# Sniffer Function
def sniffer_core():
    print("\n_____Sniffing Parameters_____")
    print("Awesome! Do you want to: ")
    print("1) Do General Sniffing")
    print("2) Specify Sniffing Attributes")
    userChoice=int(input("Input 1/2: "))
    if userChoice ==1 :
            print("Default Settings==> Sniff 20 Packets, Timeout = 30 ")
            print("Sniffing in process.......")
            sniffedPackets=sniff(count=20,timeout=30) #fix prn=
            sniffedPackets.nsummary()
            print("sniffing complete")
    elif userChoice ==2:
            print("So you're into details? So are we..")
            iface_user= getInterface()
            filter_user=getFilter()
            count_user=getCount()
            timeout_user=getTimeout()

            print("________Summary of Selections________")
            if iface_user== "any":
                print("Interface: " + iface_user)
            elif not iface_user== "any":
                print("Interface: " + iface_user)

            if (filter_user == "none"):
                print("Filter: " + filter_user)
                filter_user = ""
            elif (not filter_user == "none"):
                print("Filter: " + filter_user)

            if (count_user > 0):
                print("Packets to Sniff: " + count_user)
            elif (count_user == -1):
                print("Packets to Sniff: " + str(20) +" [default]")
                count_user=20

            if (timeout_user > 0):
                print("Timeout: " + timeout_user)
            elif (timeout_user == -1):
                print("Timeout: " + str(30) + " [default]")
                timeout_user=30

            if iface_user == "any":
                sniffedPackets2 = sniff(filter=filter_user,count=count_user,timeout=timeout_user)  # fix prn=
            elif not iface_user == "any":
                sniffedPackets2 = sniff(iface=iface_user, filter=filter_user, count=count_user,timeout=timeout_user)  # fix prn=

            print(sniffedPackets2.nsummary())
            print("sniffing complete")

# ARP Ping Function
def arp_core():
    print("\n_____ARP Ping Parameters_____")
    targetIP = str(input("Target IP: "))
    arping(targetIP)

# Traceroute Function
def traceroute_core():
    print("\n_____Traceroute Parameters_____")
    # user inputs target to traceroute
    target=[]
    numberOfTargets=int(input("Number of Targets: "))
    x=0
    for x in range(numberOfTargets):
        target.append(input("Target "+str(x+1)+": "))
    # user inputs maximum time to live
    maxTimeToLive=int(input("Maximum Time To Live: "))
    # Tracerout the target with respect to the maxttl
    traceroute(target,maxttl=maxTimeToLive)

# Printing Sniffer Name and Welcome SCreen
def welcomeScreen():
    print("----------------------------------------------------------------------")
    x=' '
    print(Fore.RED+"\t@@@@@@@@"+3*x+"@@@"+4*x+"@"+3*x+"@"+3*x+"@@@@@@@@"+3*x+"@@@@@@@@"+2*x+"@@@@@@@"+3*x+"@@@@@")
    print(4*x+"@\t\t"+3*x+"@"+2*x+"@"+3*x+"@"+3*x+"@"+3*x+"@"+10*x+"@"+9*x+"@"+9*x+"@"+4*x+"@")
    print("\t@@@@@@@@"+3*x+"@"+3*x+"@"+2*x+"@"+3*x+"@"+3*x+"@@@@@"+6*x+"@@@@@"+5*x+"@@@@@"+5*x+"@@@@@")
    print("\t\t\t@"+2*x+"@"+4*x+"@"+1*x+"@"+3*x+"@"+3*x+"@"+10*x+"@"+9*x+"@"+9*x+"@"+2*x+"@")
    print("\t@@@@@@@@"+3*x+"@"+5*x+"@@"+3*x+"@"+3*x+"@"+10*x+"@"+9*x+"@@@@@@@"+3*x+"@"+3*x+"@")
    print(Fore.BLUE+"\n\t\t\t\t\t\t[Welcome to Sniffer]")
    print(Fore.GREEN+"\t\t\t  Use wisely and don't do anything illegal")
    print(Fore.BLUE)
# Main Function
def main():
    welcomeScreen()
    welcome= str(raw_input("Are you ready to have some fun? [y/n]:  "))
    if welcome.lower()=="y":
        choice_options()
    else:
        print("Goodbye")

# Running the program
main()

