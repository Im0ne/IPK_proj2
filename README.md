# Documentation for Network Sniffer Application

## Content Structuring

- [Executive Summary](#executive-summary)
- [Theoretical Background](#theoretical-background)
- [Code Structure and Features](#code-structure-and-features)
  - [Main Components](#main-components)
  - [Interesting Code Sections](#interesting-code-sections)
- [Testing](#testing)
  - [Testing Environment](#testing-environment)
  - [Testing Methodology](#testing-methodology)
  - [Test Cases](#test-cases)
    - [ARP test case](#arp-test-case)
    - [TCP test case](#tcp-test-case)
  - [Comparison with Wireshark](#comparison-with-wireshark)
- [Bibliography](#bibliography)
- [Conclusion](#conclusion)

## Executive Summary

This document provides comprehensive documentation for a Packet Sniffer application developed in C. The application leverages the `libpcap` library to capture and analyze network packets in real-time. It is designed to filter and display various types of packets, including TCP, UDP, ICMP (v4 and v6), ARP, NDP, IGMP, and MLD, based on user-defined criteria. This documentation covers the theoretical background, code structure and testing methodology of the application.

## Theoretical Background

The Packet Sniffer application operates on the data link layer, utilizing the `libpcap` library to capture packets transmitted over the network. It can process and filter packets based on protocol type, source and destination ports, and other criteria. Understanding the following concepts is essential:

- **Packet Sniffing**: Monitoring and capturing data packets passing through a network.
- **libpcap**: A portable C/C++ library for network traffic capture. [libcap]
- **Network Protocols**: Rules and formats for communication between network devices. This application focuses on TCP, UDP, ICMP [RFC792] and [RFC4443], ARP [RFC826], NDP [RFC4861], IGMP [RFC3376], and MLD [RFC3810].

## Code Structure and Features

### Main Components

- `struct Options`: Holds user-defined options for packet filtering.
- `parse_arguments`: Parses command-line arguments and populates the `Options` structure.
- `list_interfaces`: Lists all active network interfaces.
- `open_interface`: Opens a network interface for packet capturing.
- `set_filter`: Compiles and sets a filter based on user options.
- `process_packet`: Callback function to process and print details of each captured packet.
- `capture_packets`: Starts the packet capture loop.
- `signal_handler`: Handles SIGINT signal for graceful shutdown.

### Interesting Code Sections

- **Argument Parsing**: The application uses a custom argument parsing mechanism to handle various command-line options, demonstrating a practical application of string comparison and conditional logic in C.
- **Packet Processing**: The `process_packet` function showcases how to dissect network packets and extract useful information, such as MAC addresses, IP addresses, and protocol-specific data.

## Testing

### Testing Environment

- **Operating System**: Ubuntu 20.04 LTS.
- **Network Setup**: Home Wi-Fi network.
- **Comparison Tool**: Wireshark 3.2.3 for validation.

### Testing Methodology

Tests were conducted to validate the functionality of the Packet Sniffer and compare its performance and accuracy with Wireshark. The following aspects were tested:

- **Interface Listing**: Ensured that all active interfaces are listed correctly.
- **Packet Capturing**: Verified that packets are captured accurately based on the specified filters.
- **Protocol Filtering**: Tested filtering for each supported protocol to ensure correct functionality.

### Test Cases

For testing used python script which sends some garbage packets and needed one, as reference used Wireshark.
Here is some examples of test cases:

#### ARP test case

``` wireshark
No.     Time           Source                Destination           Protocol Length Info
      1 0.000000000    00:00:00_00:00:00     Broadcast             ARP      42     ARP Announcement for 127.0.0.1

Frame 1: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface lo, id 0
Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
```

``` sniffer
timestamp: 2024-04-22T10:33:20+0200
src MAC: 00:00:00:00:00:00
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 42 bytes
ARP packet
src IP: 127.0.0.1
dst IP: 127.0.0.1
ARP operation: Reply

0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 06 00 01   ................
0x0010: 08 00 06 04 00 01 00 00 00 00 00 00 7f 00 00 01   ................
0x0020: 00 00 00 00 00 00 7f 00 00 01                     ..........
```

#### TCP test case

``` wireshark
Frame 8: 78 bytes on wire (624 bits), 78 bytes captured (624 bits) on interface lo, id 0
Ethernet II, Src: 00:00:00_00:00:00 (00:00:00:00:00:00), Dst: 00:00:00_00:00:00 (00:00:00:00:00:00)
Internet Protocol Version 6, Src: ::1, Dst: ::1
Internet Control Message Protocol v6

No.     Time           Source                Destination           Protocol Length Info
      9 19.920306433   127.0.0.1             127.0.0.1             TCP      79     20 → 4567 [SYN] Seq=0 Win=8192 Len=25 [TCP segment of a reassembled PDU]
```

``` sniffer
timestamp: 2024-04-22T10:33:42+0200
src MAC: 00:00:00:00:00:00
dst MAC: ff:ff:ff:ff:ff:ff
frame length: 79 bytes
src port: 20
dst port: 4567
src IP: 127.0.0.1
dst IP: 127.0.0.1

0x0000: ff ff ff ff ff ff 00 00 00 00 00 00 08 00 45 00   ..............E.
0x0010: 00 41 00 01 00 00 40 06 7c b4 7f 00 00 01 7f 00   .A....@.|.......
0x0020: 00 01 00 14 11 d7 00 00 00 00 00 00 00 00 50 02   ..............P.
0x0030: 20 00 44 ed 00 00 6e 6f 20 77 61 79 20 74 68 69    .D...no way thi
0x0040: 73 20 69 73 20 74 63 70 20 70 61 63 6b 65 74      s is tcp packet
```

> Note
Full testing results can be found in folder `tests` with the testing script

### Comparison with Wireshark

- **Accuracy**: Both tools captured and displayed packets accurately. However, Wireshark provides more detailed analysis and a graphical interface.
- **Performance**: The Packet Sniffer demonstrated comparable performance to Wireshark for basic packet capturing and filtering tasks.

## Conclusion

The Packet Sniffer application serves as a lightweight, command-line alternative to graphical network analysis tools like Wireshark. It demonstrates effective use of the `libpcap` library for packet capturing and filtering, providing a solid foundation for further development and customization.

## Bibliography

- **libpcap Documentation**: [libcap] [https://www.tcpdump.org/manpages/pcap.3pcap.html](https://www.tcpdump.org/manpages/pcap.3pcap.html)
- **TCP (Transmission Control Protocol)**:
  - [RFC9293] [https://datatracker.ietf.org/doc/html/rfc9293](https://datatracker.ietf.org/doc/html/rfc9293)

- **UDP (User Datagram Protocol)**:
  - [RFC768] [https://tools.ietf.org/html/rfc768](https://tools.ietf.org/html/rfc768)

- **ICMP (Internet Control Message Protocol)**:
  - For IPv4 - [RFC792] [https://tools.ietf.org/html/rfc792](https://tools.ietf.org/html/rfc792)
  - For IPv6 - [RFC4443] [https://tools.ietf.org/html/rfc4443](https://tools.ietf.org/html/rfc4443)

- **ARP (Address Resolution Protocol)**:
  - [RFC826] [https://tools.ietf.org/html/rfc826](https://tools.ietf.org/html/rfc826)

- **NDP (Neighbor Discovery Protocol for IPv6)**:
  - [RFC4861] [https://tools.ietf.org/html/rfc4861](https://tools.ietf.org/html/rfc4861)

- **IGMP (Internet Group Management Protocol)**:
  - For IGMPv3 - [RFC3376] [https://tools.ietf.org/html/rfc3376](https://tools.ietf.org/html/rfc3376)

- **MLD (Multicast Listener Discovery for IPv6)**:
  - For MLDv2 - [RFC3810] [https://tools.ietf.org/html/rfc3810](https://tools.ietf.org/html/rfc3810)
