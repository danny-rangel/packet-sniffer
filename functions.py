import struct
import socket

# function for unpacking data from the ethernet frame
def grab_ethernet_frame(packet_data):
    # look at and unpack the first 14 bytes - RECV 6 - SENDER 6 - TYPE 2
    destination_mac_address, source_mac_address, type = struct.unpack('! 6s 6s H', packet_data[:14])
    # return as well with the rest of the data, or the PAYLOAD
    return (format_mac_address(destination_mac_address),
    format_mac_address(source_mac_address), socket.htons(type), packet_data[14:])


# function that returns a formatted MAC address
def format_mac_address(address):
    # pass a function and an iterable, and format to two decimal places
    bytes_string = map('{:02x}'.format, address)

    # join the individual chunks with colons
    mac_address = ':'.join(bytes_string)

    # capitalize all the letters
    mac_address.upper()

    # return the formatted mac address
    return mac_address


# function that unpacks the IPv4 packet
def unpack_ipv4(data):
    # placing version and header length from the first byte of data passed in
    version_header_length = data[0]

    # take entire byte and bit shift it 4 to the right to get the version only
    version = version_header_length >> 4

    # take version header length and & by 15 and multiply it by 4 to get header length
    # this will give us the start of the rest of data
    header_length = (version_header_length & 15) * 4

    # data unpacked in certain format, from beginning of data to 20 bytes
    ttl, protocol, source_address, destination_address = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    # return all the data and also the data from the end of the header to the end
    return (version, header_length, ttl, protocol, format_ipv4(source_address),
    format_ipv4(destination_address), data[header_length:])




# function that returns formatted IPv4 address
# 127.0.0.1
def format_ipv4(address):
    # Grab each chunk, change to a string, and add the period in between
    formatted_ipv4_address = '.'.join(map(str, address))
    return formatted_ipv4_address



# function that unpacks the ICMP packet
def unpack_icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    # return portions of icmp packet with the payload as well
    return type, code, checksum, data[4:]


# function that unpacks the TCP segment
def unpack_tcp_segment(data):
    (source_port, destination_port, sequence_number, acknowledgement_number,
    offset_reserved_and_flags) = struct.unpack('! H H L L H', data[:14])

    # bit shifting for offset, reserved, and flags
    # grab the first 16 bits and bit shift so that we only have the offset
    data_offset = (offset_reserved_and_flags >> 12) * 4
    # more bit shifting for all the flags
    URG = (offset_reserved_and_flags & 32) >> 5
    ACK = (offset_reserved_and_flags & 16) >> 4
    PSH = (offset_reserved_and_flags & 8) >> 3
    RST = (offset_reserved_and_flags & 4) >> 2
    SYN = (offset_reserved_and_flags & 2) >> 1
    FIN = offset_reserved_and_flags & 1

    # return everything along with all of the data after the offset
    return (source_port, destination_port, sequence_number, acknowledgement_number,
    URG, ACK, PSH, RST, SYN, FIN, data[data_offset:])



# function that unpacks the UDP segment
def unpack_udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]
