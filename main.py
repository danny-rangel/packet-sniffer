'''
Daniel Rangel
Carlos Serna
Nino Vilagi

CPSC 353

Packet Sniffer
'''

import socket

# importing the helper functions for main loop from functions.py
from functions import (grab_ethernet_frame, format_mac_address,unpack_ipv4,
format_ipv4, unpack_icmp_packet, unpack_tcp_segment, unpack_udp_segment)

# importing the print functions for main loop from printer.py
from printer import (print_ethernet_header, print_unknown_data, print_ipv4_packet_header,
print_icmp_packet, print_tcp_segment, print_udp_segment)


# main function
def main():
    # create the web socket
    connection_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # main loop that goes on forever waiting for packets
    while True:
        # receive the packets from our socket and store in variables
        packet_data, address = connection_socket.recvfrom(65536)

        # grab all the packet information and store into variables
        destination_mac_address, source_mac_address, type, payload = grab_ethernet_frame(packet_data)

        # Printing out the destination address, source mac address and type
        print_ethernet_header(destination_mac_address, source_mac_address, type)

        # checking the type for 8 for regular internet traffic
        # IPv4 Packet
        if type == 8:
            # If its a IPv4 Packet, we unpack it and print out its header contents
            (version, header_length, ttl, protocol, source_address,
            destination_address, data) = unpack_ipv4(payload)

            print_ipv4_packet_header(version, header_length, ttl, protocol,
            source_address, destination_address)


            # now we check the protocol number and act according to the number
            # If its 1, its an ICMP
            if protocol == 1:
                icmp_type, code, checksum, data = unpack_icmp_packet(data)

                print_icmp_packet(icmp_type, code, checksum, data)

            # If its 8, its a TCP
            elif protocol == 6:
                (source_port, destination_port, sequence_number, acknowledgement_number,
                URG, ACK, PSH, RST, SYN, FIN, data) = unpack_tcp_segment(data)

                print_tcp_segment(source_port, destination_port, sequence_number,
                acknowledgement_number,URG, ACK, PSH, RST, SYN, FIN, data)

            # If its 17, its a UDP
            elif protocol == 17:
                source_port, destination_port, length, data = unpack_udp_segment(data)

                print_udp_segment(source_port, destination_port, length, data)

            # If it's another protocol, lets just print everything
            # so that we don't run into errors while trying to unpack it
            else:
                print_unknown_data(data)



        # If its not an IPv4 Packet, lets just print out the data
        # and not try to unpack it, else we get errors
        else:
            print_unknown_data(payload)


# call main function
main()
