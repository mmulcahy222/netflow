def super_pop(byte_array, number, pop_from="beginning"):
	'''
	param: byte_arrya, amount, pop_from (default: beginning)
	return: small byte_array
	NOTE: no need to return the remainder of the array. The pop operation already does it through reference by the list type itself.
	'''
	byte_array_chunk = bytearray()
	pop_from_where = 0 if pop_from == 'beginning' else -1
	for i in range(number):
		byte_array_chunk.append(byte_array.pop(pop_from_where))
	return byte_array_chunk
def binary_stream(bytes):
	'''
	param: bytes, bytearray
	return: long binary string - 0011000111010101110011
	'''
	#format converts integer into binary with leading zeroes
	#slicing bytearray returns another bytearray, but iterating through it (or having integer in getitem like bytes[2] returns an integer value)
	return '-'.join([format(byte_integer_value,'08b') for byte_integer_value in bytes])
def mac_format(bytes):
	'''
	param: bytes
	return: mac_string (00:5a:33:dd:00:0b)
	'''
	return ':'.join([format(byte_decimal,'02x') for byte_decimal in bytes])
def ip_format(bytes):
	'''
	param: bytes
	return: ip_string ('52.10.82.3')
	'''
	return '.'.join(str(nibble_integer) for nibble_integer in bytes)