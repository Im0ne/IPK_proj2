/**
 * @file utils.h
 * @brief Header file for the utils module
 * @author Ivan Onufriienko
*/
#ifndef UTILS_H
#define UTILS_H
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <argp.h>
#include <stdbool.h>
#include <netinet/ether.h>
#include <netinet/icmp6.h>
#include <netinet/igmp.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include "options.h"


// Function to list all active network interfaces
void list_interfaces();

// Function to open a network interface in promiscuous mode
pcap_t* open_interface(char *interface);

// Function to compile and set a pcap filter
void set_filter(pcap_t* handle, struct Options *options);

// Helper function to format MAC addresses
char* format_mac_address(const u_char *addr);

#endif