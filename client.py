#!/usr/bin/python3

"""
    This is a simple dnsclient that supports A, AAAA, MX, SOA, NS and CNAME
    queries written in python.
"""

import sys
import socket
import binascii

from query import create_dns_query
from reply import parse_dns_reply


def main():
    """ Main function of the DNS client
    """

    usage()

    query_elem = sys.argv[1]
    query_type = sys.argv[2]

    ### Create packet according to the requested query
    packet = ""
    query = queryfactory.get_dns_query(query_elem, query_type)

    # query[0] is the packet
    packet = query[0]

    raw_reply = query_dns_server(packet)
    # query[1] is qname length
    reply = queryhandler.parse_answer(raw_reply, query[1])
    queryhandler.print_reply(reply)

    return 0


def query_dns_server(packet):
    """ Function used to create a UDP socket, to send the DNS query to the server
        and to receive the DNS reply.

    Args:
        packet = the DNS query message
    
    Returns:
        The reply of the server

    If none of the servers in the dns_servers.conf sends a reply, the program
    exits showing an error message.

    """

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error:
        #print "[Error]: Faild to create socket. Exiting..."
        exit(1)

    # get DNS server IPs from dns_servers.conf file
    dns_servers = serverconf.read_file()
    # default port for DNS
    server_port = 53

    for server_ip in dns_servers:
        got_response = False

        # send message to server
        sock.sendto(packet, (server_ip, server_port))
        # receive answer
        recv = sock.recvfrom(1024)

        # if no answer is received, try another server
        if recv:
            got_response = True
            break

    # output error message if no server could respond
    if not got_response:
        #print "[Error]: No response received from server. Exiting..."
        exit(0)

    return recv[0]



if __name__ == "__main__":
    from random import randrange
    name = sys.argv[1]
    type_ = sys.argv[2]

    print(name, type_)
    query = create_dns_query(name, type_, randrange(2**16))
    print(query)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ('127.0.0.53', 53))
    reply, l = sock.recvfrom(1024)
    print(reply)
    answer = parse_dns_reply(reply)
    print(answer)











