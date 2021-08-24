# SimpleAuthDNS

## Introduction

SimpleAuthDNS is a simple authoritative DNS server.
It was made to learn the basics of the DNS protocol and the basic processing flow of the authoritative DNS server.
Based on this code, it is possible to create an authoritative DNS server with broken or fuzzing response for testing.

## Requirement

- Python 3
- dnspython (http://www.dnspython.org/)

## Installation and Usage

```bash
pip install dnspython
git clone https://github.com/nimjim/SimpleAuthDNS.git
cd SimpleAuthDNS
python3 main.py
```

```bash
$ python3 main.py -h
usage: main.py [-h] [-s SERVER] [-p PORT] [-v] [-d] [-f FILE]

This is a simple authoritative dns.

optional arguments:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        IP address for listen. Default: all addresses
  -p PORT, --port PORT  Port for listen. Default: 53
  -v, --verbose         Print verbose output
  -d, --debug           Same as "--verbose"
  -f FILE, --file FILE  The zone file to use. Default: "./test.com.zone"
```

## Note

The following related implementations have been omitted and are not available.

- queries on qclass other than IN (CH, etc...)
- wildcard (*.test.com)
- zone transfer (IXFR, AXFR)
- transaction authentication (TSIG)
- CNANE processing
- DNAME processing
- DNSSEC processing (DNSKEY, RRSIG, DS, NSEC, NSEC3...)
- additional options such as ratelimiting, policy actions, view, etc...

The following implementations may be added in the future, but are not available at this time.

- EDNS

The following have been implemented and are available.

- query via UDP/TCP
- basic authoritative DNS processings:
  - delegation processing (NS)
  - NXDOMAIN response
  - NODATA response
  - simply return the record corresponding to qname and qtype (A, AAAA, TXT, MX, etc...)
- truncating large response
