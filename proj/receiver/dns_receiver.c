#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dns_receiver_events.c"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "dns_receiver.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#define PORT     53

//dns header structure
struct dns_packet{
   unsigned short id;
   unsigned char rd: 1;
   unsigned char tc: 1;
   unsigned char aa: 1;
   unsigned char opcode: 4;
   unsigned char qr: 1;
   unsigned char rcode: 4;
   unsigned char cd: 1;
   unsigned char ad: 1;
   unsigned char z: 1;
   unsigned char ra: 1;
   unsigned short q_count;
   unsigned short ans_count;
   unsigned short auth_count;
   unsigned short add_count;
};

//dns question structure
struct dns_end{
   unsigned short qtype;
   unsigned short qclass;
};
// decodes given bytes from hexadecimal and outputs it into bytes
void decode_base16_to_bytes(char* encoded, int encoded_len, unsigned char* bytes) {
   int i;
   for (i = 0; i < encoded_len; i += 2) {
      sscanf(encoded + i, "%2hhx", &bytes[i / 2]);
   }
}

int main(int argc, char *argv[])
{
	// argument checking
	if (argc != 3){
		fprintf(stderr, "\nERROR missing/too many args \n\ndns_receiver {BASE_HOST} {DST_DIRPATH}\n");
        exit(1);
	}
	// initializing values
	char *basehost = argv[1];
	char *dst = argv[2];
	char path[400];

	// creating socket
	int sockfd;
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		fprintf(stderr, "\nERROR socket creation failed\n");
		exit(1);
	}
	// binding socket
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	memset(&server_addr, 0, sizeof(server_addr)); 
	server_addr.sin_family = AF_INET; //using IPv4
	server_addr.sin_port = htons(PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	if((bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr))) < 0){
		fprintf(stderr, "\nERROR socket binding failed\n");
		exit(1);
	}

	memset(&client_addr, 0, sizeof(client_addr)); 
	char buffer[1024];
	unsigned int length = sizeof(client_addr); 
	// initializing values
	int file_size = 0;
	int chunkid = 0;
	char data[1000];
	unsigned char enc_data[500];
	FILE* dstfile = NULL;
	char tmp[200];

	while(1){
		// recieves a packet
		int x = recvfrom(sockfd, (char *)buffer, 1024, MSG_WAITALL, (struct sockaddr *) &client_addr, &length);
		buffer[x] = '\0';
		
		struct in_addr* client_ip = (struct in_addr*)&client_addr.sin_addr.s_addr;

		struct dns_packet *dns = NULL;
		dns = (struct dns_packet *)&buffer;
		char *qname = (char *)&buffer + sizeof(struct dns_packet);
		
		// get client basehost
		char client_bhost[100];
		memset(client_bhost, 0, 100);
		int len = qname[qname[0]+1];
		int index = 0;
		int qname_offset = qname[0] + 2;
		while(len != 0){
			for(int i = 0; i < len; i++){
				client_bhost[index] = qname[qname_offset];
				qname_offset++;
				index++;
			}
			len = qname[qname_offset];
			if (len != 0){
				client_bhost[index] = '.';
			}
			index++;
			qname_offset++;
		}

		if(!strcmp(client_bhost, basehost)){
			// client and server basehosts are the same
			memset(data, 0, 1000);
			memcpy(data, qname + 1, qname[0]);
			
			if (!strcmp(data, "close")){
				// recieved packet is the last packet indicating the end of the connection with the current client
				fclose(dstfile);
				dns_receiver__on_transfer_completed(path, file_size);
				chunkid = 0;
				file_size = 0;
			}
			else{
				// decode recieved data
				memset(enc_data, 0, 500);
				decode_base16_to_bytes(data, qname[0], enc_data);
				if(dns->id == htons(0)){
					// recieved packet is the first one from the current client
					dns_receiver__on_transfer_init(client_ip);
					//looking for name of the file to be saved
					char dst_dir[300];
					memset(dst_dir, 0, 300);
					strncpy(dst_dir, dst, strlen(dst));
					char filename[90];
					memset(filename, 0, 90);
					int findex = 0;
					
					for (int i = 0; i < qname[0]/2; i++){
						if(enc_data[i] == '/'){
							memset(tmp, 0, 200);
							strncpy(tmp, dst_dir, strlen(dst_dir));
							sprintf(dst_dir, "%s/%s", tmp, filename);
							// checking if the given directory exists, if not creates it
							struct stat st = {0};
							if (stat(dst_dir, &st) == -1) {
    							mkdir(dst_dir, 0700);
							}
							memset(filename, 0, 100);
							findex = 0;
						}
						else{
							filename[findex] = enc_data[i];
							findex++;
						}
					}

					memset(path, 0, 400);
					sprintf(path, "%s/%s", dst_dir, filename);
					
					// opens the file for writing in the recieved data
					dstfile = fopen(path, "wb");
					if (dstfile == NULL) {
						fprintf(stderr, "\nError file could not be opened\n");
						exit(1);
					}
				}
				else{
					// write the recieved decoded data to the file
					chunkid++;
					dns_receiver__on_chunk_received(client_ip, path, chunkid, qname[0]);
					dns_receiver__on_query_parsed(path, qname);
					fwrite(enc_data, 1, qname[0] / 2, dstfile);
					fflush(dstfile);
					file_size += (qname[0] / 2);
				}
			}
		}
		// send reply to client
		dns->qr = htons(1);
		if (sendto(sockfd, (char*)buffer, sizeof(struct dns_packet) + strlen(qname) + 1 + sizeof(struct dns_end), MSG_CONFIRM, (struct sockaddr *) &client_addr, sizeof(client_addr)) < 0){
			printf("Failed to send ack to client\n");
         	return 1;
		}
	}
	return 0;
}