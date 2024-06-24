CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

# Object files
OBJS = main.o options.o packet_processor.o utils.o 

# Executable name
EXEC = ipk-sniffer

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) -o $(EXEC) $(OBJS) $(LDFLAGS)

main.o: main.c options.h utils.h packet_processor.h 
	$(CC) $(CFLAGS) -c main.c

options.o: options.c options.h
	$(CC) $(CFLAGS) -c options.c

packet_processor.o: packet_processor.c packet_processor.h options.h utils.h
	$(CC) $(CFLAGS) -c packet_processor.c

utils.o: utils.c utils.h options.h
	$(CC) $(CFLAGS) -c utils.c

clean:
	rm -f $(OBJS) $(EXEC)