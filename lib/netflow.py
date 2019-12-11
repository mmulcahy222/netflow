import struct
from collections import OrderedDict
from .packet_helper import *

class Netflow():
	netflow_template_field_data = {"21": {"type":"LAST_SWITCHED", }, "22": {"type":"FIRST_SWITCHED", }, "1": {"type":"BYTES", }, "2": {"type":"PKTS", }, "10": {"type":"INPUT_SNMP", }, "14": {"type":"OUTPUT_SNMP", }, "8": {"type":"IP_SRC_ADDR", }, "12": {"type":"IP_DST_ADDR", }, "4": {"type":"PROTOCOL", }, "5": {"type":"IP_TOS", }, "7": {"type":"L4_SRC_PORT", }, "11": {"type":"L4_DST_PORT", }, "48": {"type":"FLOW_SAMPLER_ID", }, "51": {"type":"FLOW_CLASS", }, "15": {"type":"IP_NEXT_HOP", }, "13": {"type":"DST_MASK", }, "9": {"type":"SRC_MASK", }, "6": {"type":"TCP_FLAGS", }, "61": {"type":"DIRECTION", }, "17": {"type":"DST_AS", }, "16": {"type":"SRC_AS", } }
	netflow_bytes = b''
	template_found = False
	templates = {}
	flows = []
	netflow_d = {}
	netflow_header_length = 20
	def __init__(self):
		pass
	def netflow_orchestrator(self,netflow_bytes):
		self.netflow_extract(netflow_bytes)
	def netflow_extract(self,netflow_bytes):
		#########################
		#
		#    NETFLOW HEADER
		#
		#########################
		#VERSION
		#	2 BYTES-16 BITS
		#COUNT
		#	2 BYTES-16 BITS
		#SYS UPTIME
		#	4 BYTES-32 BITS
		#TIMESTAMP
		#	4 BYTES-32 BITS
		#FLOW SEQUENCE (Identification)
		#	4 BYTES-32 BITS
		#SOURCE ID
		#	4 BYTES-32 BITS
		netflow_header = netflow_bytes[0:20]
		netflow_version_i, flowset_counts_i, system_uptime_f, unix_seconds_i, package_flow_sequence_i, netflow_source_id_i = struct.unpack('!1H1H1f1L1L1L',netflow_header)
	def netflow_flowset(self,netflow_bytes):
		#########################
		#
		#    FLOWSET HEADER
		#
		#########################
		#TYPE:
		#	2 BYTES-16 BITS
		#NAME:
		#	2 BYTES-16 BITS
		#GET FLOWSETS
		flowset_index = 20
		#Value to leave loop
		netflow_bytes_length = len(netflow_bytes)
		#retrieve flowsets
		while True:
			flowset_type = struct.unpack('!1H',netflow_bytes[flowset_index:flowset_index+2])[0] #1H is unsigned integer, 2 bytes
			flowset_length = struct.unpack('!1H',netflow_bytes[flowset_index+2:flowset_index+4])[0]
			flowset_bytes = netflow_bytes[flowset_index:flowset_index+flowset_length]
			#Vastly important to iterate
			flowset_index += flowset_length
			#IF FLOWSET ID IS ZERO, IT'S A TEMPLATE (2 BYTES)
			if flowset_type == 0:
				self.netflow_template(flowset_bytes)
			#IF FLOWSET ID IS 256, IT HAS DATA AND IT WILL BE THIS THE MAJORITY OF THE TIME. Will look like \x01\x00 (little endian) or \x00\x01 (big endian)
			elif flowset_type == 256:
				self.netflow_flow_data(flowset_bytes)
			#Obviously, when there's no more flowsets, leave the loop. Ordinarily, do while loops would be here
			if flowset_index >= netflow_bytes_length:
				break
	def get_netflow_template_field_name(self,template_field_id):
		'''
		param: template_field_id (Integer)
		return: the template field name from the dict
		'''
		return self.netflow_template_field_data.get(str(template_field_id),{}).get('type')
	def netflow_template(self,flowset_bytes):
		'''
		param: BYTES OF JUST THE FLOWSET
		return: RETURNS NOTHING, BUT FILLS UP SELF.TEMPLATES FOR OTHER FUNCTIONS TO WORK ON
		'''
		# flowset_type = flowset_bytes[0:2]
		# flowset_byte_length = flowset_bytes[2:4]
		template_id = struct.unpack('!1H',flowset_bytes[4:6])[0]
		template_field_count = struct.unpack('!1H',flowset_bytes[6:8])[0]
		netflow_template_ordered_dict = OrderedDict()
		#bytes where template schema is located
		template_offset = 8
		#byets
		size_of_template_field = 4
		template_fields_length = size_of_template_field * template_field_count + template_offset
		for template_index in range(template_offset,template_fields_length,size_of_template_field):
			template_field_type = struct.unpack("!1H",flowset_bytes[template_index:template_index+2])[0]
			template_field_length = struct.unpack("!1H",flowset_bytes[template_index+2:template_index+4])[0]
			# print(template_field_type,template_field_length)
			#look in the netflow templates and compile an ordered dictionary/JSON, which corresponds to the order of the netflow fields
			netflow_template_ordered_dict[self.get_netflow_template_field_name(template_field_type)] = template_field_length
			#handle multiple templates that may be existing in netflow, with primary key being the template id
			self.templates[template_id] = {}
			self.templates[template_id]['template'] = netflow_template_ordered_dict
			self.templates[template_id]['length'] = sum(list(netflow_template_ordered_dict.values()))
		#self.templates
		# {256: {'template': OrderedDict([('LAST_SWITCHED', 4), ('FIRST_SWITCHED', 4), ('BYTES', 4), ('PKTS', 4), ('INPUT_SNMP', 2), ('OUTPUT_SNMP', 2), ('IP_SRC_ADDR', 4), ('IP_DST_ADDR', 4), ('PROTOCOL', 1), ('IP_TOS', 1), ('L4_SRC_PORT', 2), ('L4_DST_PORT', 2), ('FLOW_SAMPLER_ID', 1), ('FLOW_CLASS', 1), ('IP_NEXT_HOP', 4), ('DST_MASK', 1), ('SRC_MASK', 1), ('TCP_FLAGS', 1), ('DIRECTION', 1), ('DST_AS', 2), ('SRC_AS', 2)]), 'length': 48}}
		# print(self.templates)
	def netflow_flow_data(self,flowset_bytes):
		'''
		param: BYTES OF JUST THE FLOWSET
		return: NOTHING, it just fills up self.flowss
		'''
		# flowset_type = flowset_bytes[0:2]
		# LEAVE IF TEMPLATES HASN'T BEEN FILLED
		if len(self.templates) == 0:
			# print("NO TEMPLATE YET")
			return
		# flowset_byte_length = flowset_bytes[2:4]
		flowset_bytes_length = len(flowset_bytes)
		#initialize, and flow_index is distance of bits from where the flows starts inside of flowset. In Netflow v9, distance is 4
		flow_index = 4
		flow_field_index = flow_index
		#self.templates.templatesa
		template_schema = self.templates.get(256,{}).get("template")
		#IMPORTANT Change 256 if a different template_id can be discovered. Determined by sum of template fields
		flow_length = int(self.templates.get(256,{}).get("length"))
		#StructRepresentation
		struct_dict = {1:'1B',2:'1H',4:'1L',8:'1Q'}
		flow_neat_values_dict = OrderedDict()
		flows = []
		while True:
			#individual flow here
			flow_bytes = flowset_bytes[flow_index:flow_index + flow_length]
			for flow_field_name, flow_field_length in template_schema.items():
				#DO NOT EXCEED 
				if flow_field_index >= flowset_bytes_length:
					break
				#Length 1,2,4,8 representing Netflow Value
				flow_value_bytes = flowset_bytes[flow_field_index:flow_field_index+flow_field_length]
				struct_pattern = "!" + struct_dict.get(flow_field_length)
				# print(flow_field_name,flow_field_length, struct_pattern,flow_value_bytes,flow_field_index)
				flow_neat_values_dict[flow_field_name] = struct.unpack(struct_pattern,flow_value_bytes)[0]
				flow_field_index += flow_field_length
			#increment to move further
			flow_index += flow_length
			if flow_index >= flowset_bytes_length:
				break
		def int_to_ip(ip_int):
			int_to_bytes = int.to_bytes(ip_int,4,byteorder="big")
			return ip_format(int_to_bytes)
		#CLEAN UP THE DATA
		flow_neat_values_dict['IP_DST_ADDR'] = int_to_ip(flow_neat_values_dict['IP_DST_ADDR'])
		flow_neat_values_dict['IP_SRC_ADDR'] = int_to_ip(flow_neat_values_dict['IP_SRC_ADDR'])
		#append
		self.flows.append(flow_neat_values_dict)

