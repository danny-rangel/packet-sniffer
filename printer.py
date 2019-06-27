import textwrap

def print_ethernet_header(destination_mac_address, source_mac_address, type):
    print('\nPacket Information:')
    print(f'Destination: {destination_mac_address}, Source: {source_mac_address}, Type: {type}')

def print_unknown_data(data):
    print('\t\tData:')
    print(format_multiple_lines('\t\t\t', data))

def print_ipv4_packet_header(version, header_length, ttl, protocol, source_address, destination_address):
    print('\tIPv4 Packet:')
    print(f'\t\tVersion: {version}, Header Length: {header_length}, TTL: {ttl}')
    print(f'\t\tProtocol: {protocol}, Source Address: {source_address}, Destination Address: {destination_address}')

def print_icmp_packet(icmp_type, code, checksum, data):
    print('\t\tICMP Packet:')
    print(f'\t\t\tType: {icmp_type}, Code: {code}, Checksum: {checksum}')
    print(format_multiple_lines('\t\t\t\t', data))

def print_tcp_segment(source_port, destination_port, sequence_number,
    acknowledgement_number,URG, ACK, PSH, RST, SYN, FIN, data):
    print('\t\tTCP Segment:')
    print(f'\t\t\tSource Port: {source_port}, Destination Port: {destination_port}')
    print(f'\t\t\tSequence Number: {sequence_number}, Acknowledgement Number: {acknowledgement_number}')
    print('\t\t\tFlags:')
    print(f'\t\t\t\tURG: {URG}, ACK: {ACK}, PSH: {PSH}, RST: {RST}, SYN: {SYN}, FIN: {FIN}')
    print('\t\t\tData:')
    print(format_multiple_lines('\t\t\t\t', data))

def print_udp_segment(source_port, destination_port, length, data):
    print('\t\tUDP Segment:')
    print(f'\t\t\tSource Port: {source_port}, Destination Port: {destination_port}, Length: {length}')
    print('\t\t\tData:')
    print(format_multiple_lines('\t\t\t\t', data))

# formatting function
def format_multiple_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
