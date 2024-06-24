/**
 * @file options.h
 * @brief Header file for the options module
 * @author Ivan Onufriienko
*/

#ifndef OPTIONS_H
#define OPTIONS_H
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Options {
    char *interface;
    bool show_tcp;
    bool show_udp;
    int port_destination;
    int port_source;
    bool show_icmp4;
    bool show_icmp6;
    bool show_arp;
    bool show_ndp;
    bool show_igmp;
    bool show_mld;
    int num_packets;
};

void initialize_options(struct Options *options);
void parse_arguments(int argc, char *argv[], struct Options *options);

#endif