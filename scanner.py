#This is a network  scanner

import scapy.all as scapy

def scan(ip):
    #Create a ARP frame
    arp_request = scapy.ARP(pdst=ip)

    #Create ethernet frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    #Create a combining object
    arp_request_broadcast = broadcast/arp_request

    #Send packet to network and parse a response (timeout we need
    # because if we dont have response  programm must be continue)
    answered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False)[0]

    #list_item = []

    file = open('scan.txt', 'w')

    for element in answered_list:
            # Print a header of our loop
            file.write("IP\t\t\tMACAddress\n")
            file.write(element[1].psrc + "\t\t" + element[1].hwsrc)

    #result_list = [list_header, list_item]
    file.close()

if __name__ == '__main__':
    scan("10.6.2.1/24")
