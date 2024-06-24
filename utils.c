/**
 * @file utils.c
 * @brief Implementation file for the utils module
 * @author Ivan Onufriienko
 */

#include "utils.h"
#include "options.h"

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    
    for (pcap_if_t *dev = interfaces; dev != NULL; dev = dev->next) {
        printf("%s\n", dev->name);
    }
    
    pcap_freealldevs(interfaces);
}

pcap_t* open_interface(char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }
    
    return handle;
}

void set_filter(pcap_t* handle, struct Options *options) {
    char filter_exp[1000] = "";
    struct bpf_program fp;
    int added = 0; // Track if any filter has been added

    // Initialize filter expression based on user options
    if (options->show_tcp) {
        strcat(filter_exp, "tcp");
        added = 1;
    } 
    
    if (options->show_udp) {
        if (added) strcat(filter_exp, " or ");
        strcat(filter_exp, "udp");
        added = 1;
    }

    if (options->show_icmp4) {
        if (added) strcat(filter_exp, " or ");
        strcat(filter_exp, "icmp");
        added = 1;
    }

    if (options->show_icmp6 || options->show_ndp || options->show_mld) {
        if (added) strcat(filter_exp, " or ");
        strcat(filter_exp, "icmp6");
        added = 1;
    }

    if (options->show_arp) {
        if (added) strcat(filter_exp, " or ");
        strcat(filter_exp, "arp");
        added = 1;
    }

    if (options->show_igmp) {
        if (added) strcat(filter_exp, " or ");
        strcat(filter_exp, "igmp");
        added = 1;
    }

    // Add more conditions for NDP, IGMP, MLD as needed

    // Append port filters
    if (options->port_destination > 0 && options->port_source > 0) {
        sprintf(filter_exp + strlen(filter_exp), " and port %d", options->port_destination);
    } 
    
    else if (options->port_destination > 0) {
        sprintf(filter_exp + strlen(filter_exp), " and dst port %d", options->port_destination);
    } 
    
    else if (options->port_source > 0) {
        sprintf(filter_exp + strlen(filter_exp), " and src port %d", options->port_source);
    }

    // Ensure there's a filter to apply
    if (strlen(filter_exp) == 0) {
        return; 
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Set the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Free the compiled filter
    pcap_freecode(&fp);
}

char* format_mac_address(const u_char *addr) {
    static char str[18];
    
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    
    return str;
}