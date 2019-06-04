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

        if ethernet_proto == 8:
            (version, header_len, ttl, proto, src, target, data) = ipv4_packet(data)
            print('\tIPv4 Packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_len, ttl))
            print('\t\tProtocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            if proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('\tICMP Packet:')
                print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print(format_lines('\t\t\t', data))

            elif proto == 6:
                src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('\tTCP Segment:')
                print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('\t\tSequence: {}, Acknowledgement: {}'.format(sequence, acknowledgement))
                print('\t\tFlags:')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\tData:')
                print(format_lines('\t\t\t', data))
            
            elif proto == 17:
                src_port, dest_port, length, data = udp_segment(data)
                print('\tUDP Segment:')
                print('\t\tSource Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length))

            else:
                print('\tData:')
                print(format_lines('\t\t', data))
            
        else:
            print('\tData:')
            print(format_lines('\t\t', data))



# function for unpacking the ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]

# function that returns formatted MAC address
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()


# function that unpacks the IPv4 packet
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_len, ttl, protocol, ipv4(src), ipv4(target), data[header_len:]


# function that returns formatted IPv4 address
def ipv4(address):
    return '.'.join(map(str, address))


# function that unpacks the ICMP packet
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# function that unpacks the TCP segment
def tcp_segment(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# function that unpacks the UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


# formatting function
def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
        

main()