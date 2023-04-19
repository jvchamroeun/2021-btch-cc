#!/usr/bin/python
import sys 
from scapy.all import *

dest = None
pkt = None

#-----------------------------------------------------------------------------
# FUNCTION:    packet_forge 
#  
#  DATE:        September 28, 2021
#  
#  REVISIONS:   
#  
#  DESIGNER:    Jason Soukchamroeun
#  
#  PROGRAMMER:  Jason Soukchamroeun
#  
#  INTERFACE:   def packet_forge(message)
#               message - character value from message
#  
#  RETURNS:     Forged packet(s) using scapy
# 
#  NOTES: Craft packets, source port of the TCP header will contain data 
#         store as a decimal value. Packet will set flag to Echo bit to let
#         server know that the packet is part of the covert channel
# 
# ----------------------------------------------------------------------------

def packet_forge(message):
	global pkt
	global dest

	dest = str(sys.argv[1])
	char = ord(message)
	flag = "E" 

	pkt=IP(dst=dest)/UDP(sport=char, dport=RandNum(0, 65535), flags=flag)

	return pkt

#-----------------------------------------------------------------------------
# FUNCTION:    main 
#  
#  DATE:        September 28, 2021
#  
#  REVISIONS:   
#  
#  DESIGNER:    Jason Soukchamroeun
#  
#  PROGRAMMER:  Jason Soukchamroeun
#  
#  INTERFACE:   def main()
#  
#  RETURNS:     Result on success or failure.
# 
#  NOTES: Main entry point into the program. Initializes command-line argument
#         parsing. Send's user message based on input.
# 
# ----------------------------------------------------------------------------

def main():
	while True:
		message = input('Enter your message: ')
		message += "\n"
		print("Sending data: " + message)
		for character in message:
			new_pkt = packet_forge(character)
			send(new_pkt)

if __name__ == "__main__":
	try:
		if len(sys.argv) != 2:
			print("Usage: client.py <host_ip>")
			sys.exit()
		else:
			main()
	except KeyboardInterrupt:
		print('Cancelled script.')
		sys.exit(0)

