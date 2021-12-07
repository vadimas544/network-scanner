This is a scanner of network

Steps to create a network scanner is next:
 - import a network library SCAPY, who can work with network protocols
 - use a ARP function from this library to ask who has target IP (create a object of ARP request)
 - Set destination MAC to broadcast MAC (create a object of broadcast frame)
 - combine together this two objects, and receive one object with all these parameters
 - then we have parse a response and extract a useful info in loop
 
 

