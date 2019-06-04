import socket
import struct
import textwrap

# function for unpacking the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

# function that returns formatted MAC address
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()