#! /usr/bin/env python3

import argparse
import socket
import select
import threading

import dns.zone
import dns.name
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rdataclass
import dns.query

SERVER = ''  # for all addresses
PORT = 53
DEBUG_MODE = False
zonefile = './test.com.zone'
zone = dns.zone.from_file(zonefile, relativize=False)

def process_command_line_args():
    global SERVER, PORT, DEBUG_MODE, zone

    parser = argparse.ArgumentParser(
        description='This is a simple authoritative dns.')
    parser.add_argument('-s', '--server',
                        help='IP address for listen. Default: all addresses')
    parser.add_argument('-p', '--port',
                        help='Port for listen. Default: 53')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print verbose output')
    parser.add_argument('-d', '--debug', action='store_true',
                        help='Same as "--verbose"')
    parser.add_argument('-f', '--file',
                        help='The zone file to use. Default: "./test.com.zone"')
    args = parser.parse_args()

    if args.server:
        SERVER = args.server
    if args.port:
        PORT = int(args.port)
    if args.debug or args.verbose:
        DEBUG_MODE = True
        print('running in DEBUG MODE')
    if args.file:
        zone = dns.zone.from_file(args.file, relativize=False)

def setup_sockets(server, port):
    sock_udp4 = create_udp4_socket(server, port)
    sock_udp6 = create_udp6_socket(server, port)
    sock_tcp4 = create_tcp4_socket(server, port)
    sock_tcp6 = create_tcp6_socket(server, port)

    fd_udp4 = sock_udp4.fileno()
    fd_udp6 = sock_udp6.fileno()
    fd_tcp4 = sock_tcp4.fileno()
    fd_tcp6 = sock_tcp6.fileno()

    fd_read = [fd_udp4, fd_udp6, fd_tcp4, fd_tcp6]
    sockets = {fd_udp4: sock_udp4, fd_udp6: sock_udp6,
               fd_tcp4: sock_tcp4, fd_tcp6: sock_tcp6}
    is_tcp_dict = {fd_udp4: False, fd_udp6: False, fd_tcp4: True, fd_tcp6: True}

    return fd_read, sockets, is_tcp_dict

def create_udp4_socket(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    return sock

def create_udp6_socket(host, port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    return sock

def create_tcp4_socket(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock

def create_tcp6_socket(host, port):
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(5)
    return sock

def handle_connection(sock, is_tcp):
    if is_tcp:
        conn, client_addrport = sock.accept()
        query, received_time = dns.query.receive_tcp(conn)
    else:
        query, received_time, client_addrport = dns.query.receive_udp(sock)

    if DEBUG_MODE:
        transport = "TCP" if is_tcp else "UDP"
        qname = query.question[0].name
        qtype = dns.rdatatype.to_text(query.question[0].rdtype)
        qclass = dns.rdataclass.to_text(query.question[0].rdclass)
        addr, port = client_addrport
        print('\n{} query: {} {} {} from {}#{}, id: {}'.format(
            transport, qname, qtype, qclass, addr, port, query.id))

    response = resolve_query(query)

    # Check the response size, and truncate if it exceeds 512bytes.
    if not is_tcp:
        try:
            response.to_wire(max_size=512)
        except dns.exception.TooBig:
            response.flags |= dns.flags.TC
            response.answer = []
            response.authority = []
            response.additional = []

    if DEBUG_MODE:
        print("Response for", response)

    # Response the answer. If response is None, it means query is dropped.
    if response is not None:
        if is_tcp:
            dns.query.send_tcp(conn, response)
            conn.close()
        else:
            dns.query.send_udp(sock, response, client_addrport)

def resolve_query(query):
    response = dns.message.make_response(query)
    qname = query.question[0].name
    qtype = query.question[0].rdtype
    qclass = query.question[0].rdclass

    # Refuse query if qclass is not IN
    if qclass != dns.rdataclass.IN:
        response.set_rcode(dns.rcode.REFUSED)
        return response

    # Refuse query for a different Zone
    if not qname.is_subdomain(zone.origin):
        response.set_rcode(dns.rcode.REFUSED)
        return response

    # Return NOTIMP for RR Types which SimpleAuthDNS does not support
    # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    if qtype >= 99:
        response.set_rcode(dns.rcode.NOTIMP)
        return response

    def add_additional(response, target):
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            additional_rrset = zone.get_rrset(target, rdtype)
            if additional_rrset:
                response.additional.append(additional_rrset)
        return response

    # Check for delegation
    for i in range(len(qname.labels) - len(zone.origin.labels)):
        check_name = dns.name.Name(labels=qname.labels[i:])
        ns_rdataset = zone.get_rdataset(check_name, dns.rdatatype.NS)
        if ns_rdataset:
            # do referral response
            response.authority.append(
                zone.get_rrset(check_name, dns.rdatatype.NS))
            for rdata in ns_rdataset:
                # check if ns target is in-Bailiwick or out-of-Bailiwick
                ns_target = rdata.target
                if ns_target.is_subdomain(check_name):
                    # if ns target is in-Bailiwick, add glue record
                    response = add_additional(response, ns_target)
            return response

    # Look for qname
    node = zone.get_node(qname)
    if node is None:
        # NXDOMAIN response
        response.set_rcode(dns.rcode.NXDOMAIN)
        soa_rrset = zone.get_rrset(zone.origin, dns.rdatatype.SOA)
        response.authority.append(soa_rrset)
        response.flags |= dns.flags.AA
        return response

    # Look for (qname, qtype)
    rrset = zone.get_rrset(qname, qtype)
    if rrset is None:
        # NODATA response
        response.set_rcode(dns.rcode.NOERROR)
        soa_rrset = zone.get_rrset(zone.origin, dns.rdatatype.SOA)
        response.authority.append(soa_rrset)
        response.flags |= dns.flags.AA
    else:
        response.set_rcode(dns.rcode.NOERROR)
        response.answer.append(rrset)
        response.flags |= dns.flags.AA
        # If needed, add additional section
        if qtype == dns.rdatatype.NS:
            for ns_rdata in rrset.to_rdataset():
                response = add_additional(response, ns_rdata.target)
        elif qtype == dns.rdatatype.MX:
            for mx_rdata in rrset.to_rdataset():
                response = add_additional(response, mx_rdata.exchange)
        elif qtype == dns.rdatatype.SRV:
            for srv_rdata in rrset.to_rdataset():
                response = add_additional(response, srv_rdata.target)
    return response

def main():
    process_command_line_args()
    print("SimpleAuthDNS: running")
    fd_read, sockets, is_tcp_dict = setup_sockets(SERVER, PORT)
    print("Listening on UDP and TCP port {}".format(PORT))

    while True:
        fd_read_ready, _, _ = select.select(fd_read, [], [], 5)
        for fd in fd_read_ready:
            threading.Thread(target=handle_connection,
                             args=(sockets[fd], is_tcp_dict[fd])).start()

if __name__ == '__main__':
    main()
