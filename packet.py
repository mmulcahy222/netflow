import dpkt
import struct
from lib.packet_helper import *
from lib.netflow import *
import pprint
#########################
#    VARIABLES
#########################
counter=0
ipcounter=0
tcpcounter=0
udpcounter=0
x_index = 0
x_length = 18
filename='wireshark_captures/netflow_3.pcap'
packets = []
ip_packets = []
tcp_packets = []
nf = Netflow()
#########################
#    CODE
#########################
for ts, packet in dpkt.pcap.Reader(open(filename,'rb')):
	counter += 1
	#########################
	#
	#    ETHERNET HEADER
	#
	#########################
	#Ethernet Header is first fourteen bits of the packet, from 0 to 13 in this case. Doesn't include Preamble of 8 bytes of alternative 1 & 0, and the SoF (Start Of Frame), which can be Type I or Type II
	#DESTINATION MAC ADDRESS:
	#	6 BYTES-48 BITS
	#SOURCE MAC ADDRESS:		
	#	6 BYTES-48 BITS
	#ETHER_TYPE:				
	#	2 BYTES-16 BITS
	ethernet_end = 14
	ethernet_header = packet[0:14]
	destination_mac_address_b, source_mac_address_b, ether_type_int = struct.unpack("!6s6s1H",ethernet_header)
	destination_mac_address_b = mac_format(destination_mac_address_b)
	source_mac_address_b = mac_format(source_mac_address_b)
	print(counter,destination_mac_address_b,source_mac_address_b,ether_type_int)
	#########################
	#
	#    IP HEADER
	#
	#########################
	#VERSION:								
	#	4 BITS
	#HEADER LENGTH (IHL):					
	#	4 BITS
	#TYPE OF SERVICE:			
	#	1 BYTE-8 BITS
	#TOTAL LENGTH:				
	#	2 BYTES-16 BITS
	#IDENTIFICATION:			
	#	2 BYTES-16 BITS
	#IP FLAGS (xDM):						
	#	3 BITS
	#FRAGMENT OFFSET:						
	#	13 BITS
	#TIME TO LIVE (TTL):		
	#	1 BYTE-8 BITS
	#PROTOCOL:
	#	1 BYTE-8 BITS
	#HEADER CHECKSUM:
	#	1 BYTE-8 BITS
	#SOURCE ADDRESS:
	#	4 BYTES-32 BITS
	#DESTINATION ADDRESS:
	#	4 BYTES-32 BITS
	#OPTION-PADDING:
	#	ANY AMOUNT
	#	
	#IP PACKET (0x0800 in hex)
	if ether_type_int == 2048:
		ip_start = ethernet_end
		#not accounting for options & padding yet, because struct module requires static amount
		ip_packet = packet[ip_start:ip_start+20]
		version_header_length_i, terms_of_service_b, total_length_i, identification_b, flags_fragment_offset_b, ttl_i , protocol_i ,header_checksum_b , source_ip_address_b, destination_ip_address_b = struct.unpack('!1s1s1H2s2s1B1B2s4s4s',ip_packet)
		#isolate the bits inside of bytes that have more than one field
		#Version/Header Length: ord() requires one byte, and turns into integer 
		version_integer = ord(version_header_length_i) >> 4
		header_length_bytes = ord(version_header_length_i) & int('00001111',2)
		#for some reason, it's multipled by four
		header_length_bits = header_length_bytes * 4
		#Flags/Fragment Offset Byte
		flags_fragment_offset_binary = binary_stream(flags_fragment_offset_b)
		reserved_flag = flags_fragment_offset_binary[0]
		do_not_fragment_flag = flags_fragment_offset_binary[1]
		more_fragment_flag = flags_fragment_offset_binary[2]
		fragment_offset_i = int.from_bytes(flags_fragment_offset_b,byteorder="big") & int('0001111111111111',2)
		#IP ADDRESSES
		source_ip_address = ip_format(source_ip_address_b)
		destination_ip_address = ip_format(destination_ip_address_b)
		#IP HEADER END
		ip_end = ip_start + header_length_bits
		#IF TCP PACKET
		if protocol_i == 6:
			pass
			#########################
			#
			#    TCP HEADER
			#
			#########################
			#SOURCE PORT:	
			#	2 BYTES-16 BITS
			#DESTINATION PORT:
			#	2 BYTES-16 BITS
			#SEQUENCE NUMBER:			
			#	4 BYTES-32 BITS
			#ACKNOWLEDGEMENT NUMBER:	
			#	4 BYTES-32 BITS
			#OFFSET:
			#	4 BITS
			#RESERVED
			#	4 BITS
			#TCP FLAGS
			#	1 BYTE-8 BITS
			#WINDOW SIZE
			#	2 BYTES-8 BITS
			#CHECKSUM
			#	2 BYTES-8 BITS
			#URGENT POINTER
			#	2 BYTES-8 BITS
			#OPTIONS & PASSING
			#
			#
			tcp_start = ip_end
			tcp_header = packet[tcp_start:tcp_start+20]
			tcp_source_port_i,tcp_destination_port_i,sequence_number_i,acknowledge_number_i,offset_reserved_i,tcp_flags_b,window_size_i,tcp_checksum_b,urgent_pointer_b = struct.unpack('!1H1H1L1L1B1s1H2s2s',tcp_header)
			#offset/reserved
			tcp_offset_nibbles = (offset_reserved_i >> 4) & int('00001111',2)
			tcp_offset_bits = tcp_offset_nibbles * 4
			print(counter,tcp_offset_bits)
		#IF UDP PACKET
		elif protocol_i == 17:
			#########################
			#
			#    UDP HEADER
			#
			#########################
			#SOURCE PORT:	
			#	2 BYTES-16 BITS
			#DESTINATION PORT:
			#	2 BYTES-16 BITS
			#LENGTH
			#	2 BYTES-16 BITS
			#CHECKSUM
			#	2 BYTES-16 BITS
			udp_start = ip_end
			udp_header = packet[udp_start:udp_start+8]
			udp_source_port_i,udp_destination_port_i,udp_length_i,udp_checksum_b = struct.unpack('!1H1H1H2s',udp_header)
			udp_end = ip_end + 8
			#IF NETFLOW
			if udp_destination_port_i == 2055:
				if source_ip_address == '192.168.56.3':
					# print(packet[udp_end:])
					# print("{}:".format(counter))
					nf.netflow_flowset(packet[udp_end:])
	#NOT IP PACKET
	else:
		pass



pprint.pprint(nf.flows)
pprint.pprint("\n")
pprint.pprint(len(nf.flows))
pprint.pprint("\n")


# host = socket.gethostbyname(socket.gethostname())
# s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
# s.bind((host, 0))
# s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
# s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
# while True:
# 	chunk, addr = s.recvfrom(1024)
# 	print(chunk)