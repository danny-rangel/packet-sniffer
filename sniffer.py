import socket
import struct
import textwrap



def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = conn.recvfrom(65536)
        dest_mac, src_mac, ethernet_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, ethernet_proto))


# function for unpacking the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

# function that returns formatted MAC address
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()