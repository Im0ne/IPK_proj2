/**
 * @file packet_processor.h
 * @brief Header file for the packet processor module
 * @author Ivan Onufriienko
*/

#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include "options.h"
#include "utils.h"

// Function to process captured packets
void process_packet(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

// Function to start packet capture
void capture_packets(pcap_t* handle, struct Options *options);

#endif