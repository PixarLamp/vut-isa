CC=gcc
CFLAGS  = -g -Wall -pedantic -Wextra
LFLAGS  =
.PHONY: all sender receiver
all: sender receiver

sender: dns_sender

dns_sender: sender/dns_sender.o
	$(CC) $(LFLAGS) -o dns_sender sender/dns_sender.o
sender/dns_sender.o: sender/dns_sender.c sender/dns_sender.h sender/dns_sender_events.h
	$(CC) $(CFLAGS) -c -o sender/dns_sender.o sender/dns_sender.c

receiver: dns_receiver

dns_receiver: receiver/dns_receiver.o
	$(CC) $(LFLAGS) -o dns_receiver receiver/dns_receiver.o
receiver/dns_receiver.o: receiver/dns_receiver.c receiver/dns_receiver.h receiver/dns_receiver_events.h
	$(CC) $(CFLAGS) -c -o receiver/dns_receiver.o receiver/dns_receiver.c

clean:
	$(RM) all *.o sender/*.o receiver/*.o dns_receiver dns_sender