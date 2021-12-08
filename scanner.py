#This is a network  scanner

import scapy.all as scapy
import optparse

def get_args():
    
    # Create a parser object (instance of a class OptionParser)
    parser = optparse.OptionParser()

    # Option that parser is expect from user
    parser.add_option("-n", "--network", dest="network", help="Network for scan IP addresses")

    (options, arguments) = parser.parse_args()

    if not options.network:
        parser.error("[-] Please specify a network, use --help for more info")

    return options



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


options = get_args()
scan(options.network)
