/**
 * @file main.c
 * @brief Main file for the packet sniffer
 * @author Ivan Onufriienko
*/


#include "options.h"
#include "packet_processor.h"
#include "utils.h"

pcap_t* handle;

// Signal handler to ensure the program can be terminated with Ctrl + C
void signal_handler() {
    pcap_breakloop(handle);
}

int main(int argc, char *argv[]){
 struct Options options;
    initialize_options(&options);
    parse_arguments(argc, argv, &options);

    if (options.interface == NULL) {
        printf("List of active interfaces:\n");
        list_interfaces();
        return EXIT_SUCCESS;
    }

    handle = open_interface(options.interface);
    signal(SIGINT, signal_handler);
    set_filter(handle, &options);
    capture_packets(handle, &options);
    pcap_close(handle);

    return EXIT_SUCCESS;
}