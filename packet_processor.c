/**
 * @file packet_processor.c
 * @brief Implementation file for the packet processor module
 * @author Ivan Onufriienko
*/
#include "packet_processor.h"

// Add this function to handle detailed ICMPv6 processing
void process_icmpv6_packet(const struct icmp6_hdr *icmp6_header, const struct Options *options) {
    char addr_str[INET6_ADDRSTRLEN];
    switch (icmp6_header->icmp6_type) {
        case ND_NEIGHBOR_SOLICIT: // 135
            if (options->show_ndp) {
                struct nd_neighbor_solicit *nd_ns = (struct nd_neighbor_solicit *)icmp6_header;
                printf("Target Address: %s\n", inet_ntop(AF_INET6, &nd_ns->nd_ns_target, addr_str, INET6_ADDRSTRLEN));
            }
            break;
        case ND_NEIGHBOR_ADVERT:
            if (options->show_ndp) {
                struct nd_neighbor_advert *nd_na = (struct nd_neighbor_advert *)icmp6_header;
                printf("Target Address: %s\n", inet_ntop(AF_INET6, &nd_na->nd_na_target, addr_str, INET6_ADDRSTRLEN));
                printf("Flags: Router=%d, Solicited=%d, Override=%d\n",
                       (nd_na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER) ? 1 : 0,
                       (nd_na->nd_na_flags_reserved & ND_NA_FLAG_SOLICITED) ? 1 : 0,
                       (nd_na->nd_na_flags_reserved & ND_NA_FLAG_OVERRIDE) ? 1 : 0);
            }
            break;
        case 130: // MLD Query
        case 131: // MLDv1 Report
        case 132: // MLD Done
        case 143: // MLDv2 Report
            if (options->show_mld) {
                struct mld_hdr *mld_header = (struct mld_hdr *)icmp6_header;
                const char *mld_type_str = "";
                switch (icmp6_header->icmp6_type) {
                    case 130: mld_type_str = "MLD Query"; break;
                    case 131: mld_type_str = "MLDv1 Report"; break;
                    case 132: mld_type_str = "MLD Done"; break;
                    case 143: mld_type_str = "MLDv2 Report"; break;
                }
                printf("MLD Type: %s\n", mld_type_str);
                printf("MLD max response code: %d\n", ntohs(mld_header->mld_maxdelay));
            }
            break;
    }
}

void print_default_packet_info(struct ether_header *eth_header, const u_char *packet, const struct pcap_pkthdr *pkthdr) {
    // Print the timestamp in RFC 3339 format
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S%z", localtime((const time_t *) &pkthdr->ts.tv_sec));
    printf("timestamp: %s\n", timestamp);

    printf("src MAC: %s\n", format_mac_address(eth_header->ether_shost));
    printf("dst MAC: %s\n", format_mac_address(eth_header->ether_dhost));
    printf("frame length: %d bytes\n", pkthdr->len);
}

void print_byte_offset(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("\n");
    
    char ascii[17];
    int line_len = 0;
    
    for (uint i = 0; i < pkthdr->len; i++) {
        
        // Print the offset at the start of each line
        if (i % 16 == 0) {
            
            if (i != 0) {
                
                while (line_len < 16) {
                    printf("   ");
                    line_len++;
                }
                
                printf("  %s\n", ascii);
            }
            
            printf("0x%04x: ", i);
            line_len = 0;
        }

        // Print the byte in hexadecimal format
        printf("%02x ", packet[i]);

        // Store the ASCII representation of the byte
        ascii[i % 16] = isprint(packet[i]) ? packet[i] : '.';
        ascii[(i % 16) + 1] = '\0';

        line_len++;
    }

    // Print the remaining ASCII representation
    while (line_len < 16) {
        
        printf("   ");
        line_len++;
    }
    
    printf("  %s\n", ascii);
    printf("\n");
}

void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct Options *options = (struct Options *) user;
    struct ether_header *eth_header = (struct ether_header *) packet;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    
    // Determine if the packet is ARP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP && options->show_arp) {
        struct ether_arp *arp_header = (struct ether_arp *)(packet + ETHER_HDR_LEN);
        print_default_packet_info(eth_header, packet, pkthdr);
        printf("ARP packet\n");
        printf("src IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_header->arp_spa));
        printf("dst IP: %s\n", inet_ntoa(*(struct in_addr *)&arp_header->arp_tpa));
        printf("ARP operation: %s\n", arp_header->arp_op == ARPOP_REQUEST ? "Request" : "Reply");
        print_byte_offset(pkthdr, packet);
    }

    // Determine if the packet is IPv4 or IPv6
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + ETHER_HDR_LEN);
        // Process IPv4 packet
        if (ip_header->ip_p == IPPROTO_TCP && options->show_tcp) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
            print_byte_offset(pkthdr, packet);
        } else if (ip_header->ip_p == IPPROTO_UDP && options->show_udp) {
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
            print_byte_offset(pkthdr, packet);
        } else if (ip_header->ip_p == IPPROTO_ICMP && options->show_icmp4) {
            struct icmp *icmp_header = (struct icmp *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("ICMP type: %d\n", icmp_header->icmp_type);
            printf("ICMP code: %d\n", icmp_header->icmp_code);
            printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
            print_byte_offset(pkthdr, packet);
        } else if (ip_header->ip_p == IPPROTO_IGMP && options->show_igmp) {
            struct igmp *igmp_header = (struct igmp *)(packet + ETHER_HDR_LEN + (ip_header->ip_hl << 2));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("IGMP type: %d\n", igmp_header->igmp_type);
            printf("IGMP code: %d\n", igmp_header->igmp_code);
            printf("src IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("dst IP: %s\n", inet_ntoa(ip_header->ip_dst));
            print_byte_offset(pkthdr, packet);
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        struct ip6_hdr *ip6_header = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);
        // Process IPv6 packet
        if (ip6_header->ip6_nxt == IPPROTO_TCP && options->show_tcp) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
            printf("src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN));
            printf("dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN));
            print_byte_offset(pkthdr, packet);
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP && options->show_udp) {
            struct udphdr *udp_header = (struct udphdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
            printf("src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN));
            printf("dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN));
            print_byte_offset(pkthdr, packet);
        } else if (ip6_header->ip6_nxt == IPPROTO_ICMPV6 && (options->show_icmp6 || options->show_ndp || options->show_mld)) {
            struct icmp6_hdr *icmp6_header = (struct icmp6_hdr *)(packet + ETHER_HDR_LEN + sizeof(struct ip6_hdr));
            print_default_packet_info(eth_header, packet, pkthdr);
            printf("src IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_src, src_ip, INET6_ADDRSTRLEN));
            printf("dst IP: %s\n", inet_ntop(AF_INET6, &ip6_header->ip6_dst, dst_ip, INET6_ADDRSTRLEN));
            printf("ICMPv6 type: %d\n", icmp6_header->icmp6_type);
            printf("ICMPv6 code: %d\n", icmp6_header->icmp6_code);
            process_icmpv6_packet(icmp6_header, options);
            print_byte_offset(pkthdr, packet);
        }
    }  
}

void capture_packets(pcap_t* handle, struct Options *options) {
    pcap_loop(handle, options->num_packets, process_packet, (u_char *) options);
}