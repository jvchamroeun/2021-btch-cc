#!/usr/bin/python 
import sys
from scapy.all import *

#-----------------------------------------------------------------------------
# FUNCTION:    parse_packet
#  
#  DATE:        September 28, 2021
#  
#  REVISIONS:   
#  
#  DESIGNER:    Jason Soukchamroeun
#  
#  PROGRAMMER:  Jason Soukchamroeun
#  
#  INTERFACE:   def parse_packet(pkt)
#               pkt - incoming packet with specified flag bit
#               
#  RETURNS:     decoded character message from sport value
# 
#  NOTES: Listens and filter covert traffic, denoted with an "E" flag
#         It then reads the data from the source port
# ----------------------------------------------------------------------------

def parse_packet(pkt):
	flag=pkt['TCP'].flags
	if flag == 0x40:
		char = chr(pkt['TCP'].sport)
		sys.stdout.write(char)

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
#  NOTES: Main entry point into the program and listens for traffic.
# 
# ----------------------------------------------------------------------------

def main():
	print("listening. . .")
	sniff(filter="tcp", prn=parse_packet)
	

if __name__ == "__main__":
		main()
