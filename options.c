/**
 * @file options.c
 * @brief Implementation file for the options module
 * @author Ivan Onufriienko
*/

#include "options.h"


void print_usage(char *program_name) {
    printf("Usage: %s [-i interface | --interface interface] {-p port [--tcp|-t] "
           "[--udp|-u]} [--arp] [--icmp4] [--icmp6] [--ndp] [--igmp] [--mld] {-n num}\n", program_name);
}

void initialize_options(struct Options *options) {
    options->interface = NULL;
    options->show_tcp = false;
    options->show_udp = false;
    options->port_destination = -1;
    options->port_source = -1;
    options->show_icmp4 = false;
    options->show_icmp6 = false;
    options->show_arp = false;
    options->show_ndp = false;
    options->show_igmp = false;
    options->show_mld = false;
    options->num_packets = 0;
}

void parse_arguments(int argc, char *argv[], struct Options *options) {
    bool port_option_used = false; // Flag to track if -p or --port is used
    
    for (int i = 1; i < argc; i++) {
        
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            
            if (++i < argc)
                options->interface = argv[i];
            else {
                options->interface = NULL;
            }
        } 
        
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            options->show_tcp = true;
        } 
        
        else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            options->show_udp = true;
        } 
        
        else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            
            if (++i < argc) {
                options->port_destination = atoi(argv[i]);
                options->port_source = atoi(argv[i]);
                port_option_used = true;
            } 
            else {
                printf("Error: Missing port number\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        } 
        else if (strcmp(argv[i], "--port-destination") == 0) {
            
            if (port_option_used) {
                printf("Error: Cannot use --port-destination or --port-source with -p\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            
            if (++i < argc) {
                options->port_destination = atoi(argv[i]);
                port_option_used = true;
            } 
            else {
                printf("Error: Missing port number for destination\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        } 
        else if (strcmp(argv[i], "--port-source") == 0) {
            
            if (port_option_used) {
                printf("Error: Cannot use --port-destination or --port-source with -p\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
            
            if (++i < argc) {
                options->port_source = atoi(argv[i]);
                port_option_used = true;
            } 
            else {
                printf("Error: Missing port number for source\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        } 
        
        else if (strcmp(argv[i], "--icmp4") == 0) {
            options->show_icmp4 = true;
        } 
        
        else if (strcmp(argv[i], "--icmp6") == 0) {
            options->show_icmp6 = true;
        } 
        
        else if (strcmp(argv[i], "--arp") == 0) {
            options->show_arp = true;
        } 
        
        else if (strcmp(argv[i], "--ndp") == 0) {
            options->show_ndp = true;
        } 
        
        else if (strcmp(argv[i], "--igmp") == 0) {
            options->show_igmp = true;
        } 
        
        else if (strcmp(argv[i], "--mld") == 0) {
            options->show_mld = true;
        } 
        
        else if (strcmp(argv[i], "-n") == 0) {
            
            if (++i < argc)
                options->num_packets = atoi(argv[i]);
            else {
                printf("Error: Missing number of packets\n");
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
            }
        } 
        else {
            printf("Error: Unknown option %s\n", argv[i]);
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
    if (!(options->show_tcp || options->show_udp) && port_option_used) {
        printf("Error: Must specify --tcp or --udp with -p\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
    if (!options->show_arp && !options->show_icmp4 && !options->show_icmp6 && !options->show_igmp && !options->show_mld && !options->show_ndp && !options->show_tcp && !options->show_udp) {
        options->show_tcp = options->show_udp = options->show_icmp4 = options->show_icmp6 = options->show_arp = options->show_ndp = options->show_igmp = options->show_mld = true;
    }
}