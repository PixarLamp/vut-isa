#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "dns_sender_events.c"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include "dns_sender.h"
#define PORT 53

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

// encodes given bytes to hexadecimal and stores into encoded
void encody_bytes_to_base16(char* bytes, int bytes_len, char* encoded){
   int i;
   for (i = 0; i < bytes_len; i++) {
      sprintf(encoded + i * 2, "%02x", (unsigned char)bytes[i]);
   }
}

//encodes basehost into qname form for dns packet 
void encode_basehost(char *basehost, char tmp_qname[100]){
   int label_cnt = 0;
   char label[63];
   int qname_index = 0;
   memset(tmp_qname, 0, 100);
   for (int i = 0; i < (int)strlen(basehost); i++){
      // finds end of each label in basehost
      if (basehost[i] == '.'){
         tmp_qname[qname_index] = label_cnt;
         qname_index++;
         for (int y = 0; y < label_cnt; y++){
            // adding currently found label to the qname
            tmp_qname[qname_index] = label[y];
            qname_index++;
         }
         memset(label, 0, 63);
         label_cnt = 0;
      }
      else{
         // saving current label
         label[label_cnt] = basehost[i];
         label_cnt++;
      }
   }
   // adding last label
   tmp_qname[qname_index] = label_cnt;
   qname_index++;
   for (int y = 0; y < (int)strlen(label); y++){
      tmp_qname[qname_index] = label[y];
      qname_index++;
   }
   tmp_qname[qname_index] = 0;
}

int main(int argc, char *argv[])
{
   char *dns_ip = "";
   char *basehost;
   char *dst;
   char *src = "";   
   int index = 0;

   // argc correctness check
   if (argc < 3 || argc > 6){
      fprintf(stderr, "\nwrong number of arguments\n");
      exit(1);
   }

   // -u arg check
   if (!(strcmp(argv[1], "-u"))){
      // contains -u
      if (argc < 5){
         fprintf(stderr, "\nmissing arguments\n");
         exit(1);
      }
      index += 2;
      dns_ip = argv[index]; 
   }
   else{
      if (argc > 4){
         fprintf(stderr, "\nmore args than allowed passed\n");
         exit(1);
      }
   }

   // init values
   basehost = argv[index+1];
   dst = argv[index+2];
   if (argc == index+4){
      // contains SRC_FILEPATH
      src = argv[argc-1];
   }
   char tmp_qname[100]; 
   encode_basehost(basehost, tmp_qname);

   if (!strlen(dns_ip)){
      // ip not given from input, getting ip from /etc/resolv.conf;
      FILE* resolvfile = fopen("/etc/resolv.conf", "r");
      if (resolvfile == NULL) {
         fprintf(stderr, "\nError file could not be opened\n");
         exit(1);
      }
      char *line = NULL;
      size_t len = 0;
      bool ipfound = false;
      
      while (!ipfound){
         getline(&line, &len, resolvfile);
         if (strncmp(line, "nameserver", 10) == 0){
            dns_ip = malloc(sizeof(char *) * strlen(line));
            strcpy(dns_ip, line+11);
            dns_ip[strlen(dns_ip)-1] = '\0';
            ipfound = true;
         }
      }
      fclose(resolvfile);
   }
   // create socket
   int sockfd;
   if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		fprintf(stderr, "\nERROR socket creation failed\n");
		exit(1);
	}
   // set socket address
   struct in_addr upstream_dns_addr;
   if(inet_pton(AF_INET, dns_ip, &upstream_dns_addr) != 1){
      fprintf(stderr, "\nError Invalid upstream DNS IP address\n");
      exit(1);   
   }
   struct sockaddr_in server_addr;
   server_addr.sin_family = AF_INET;
   server_addr.sin_port = htons(PORT);
   server_addr.sin_addr= upstream_dns_addr;

   // initialize dns packet
   struct dns_packet *dns = NULL;   
   char buffer[5000];   
   memset(buffer, 0, 1024);
   dns = (struct dns_packet *)&buffer;
   dns->id = htons(0);
   dns->qr = 0;
   dns->opcode = 0;
   dns->aa = 0;
   dns->tc = 0;
   dns->rd = 0;
   dns->cd = 0;
   dns->ra = 0;
   dns->ad = 0;
   dns->z = 0;
   dns->rcode = 0;
   dns->q_count = htons(1);
   dns->ans_count = 0;
   dns->auth_count = 0;
   dns->add_count = 0;
   
   // encoding destination file path to hex 
   // and creating qname by joining it with encoded basehost
   char dst_en[100];
   encody_bytes_to_base16(dst, strlen(dst), dst_en);
   char *qname = (char*)&buffer + sizeof(struct dns_packet);
   qname[0] = strlen(dst)*2;
   memcpy(qname + 1, dst_en, strlen(dst)*2);
   memcpy(qname + 1 + strlen(dst)*2, tmp_qname, strlen(tmp_qname) + 1);

   struct dns_end packet_end;
   packet_end.qtype = htons(1);
   packet_end.qclass = htons(1);
   memcpy(qname + strlen(qname) + 1, &packet_end, sizeof(struct dns_end));

   // sending first packet with the given filepath in it
   if (sendto(sockfd, (char*)buffer, sizeof(struct dns_packet) + strlen(qname) + 1 + sizeof(struct dns_end), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      fprintf(stderr, "\nFailed to send query to upstream DNS server\n");
      exit(1);   
   }
   dns_sender__on_transfer_init(&upstream_dns_addr);

   int chunkid = 0;
   FILE* srcfile = NULL;
   // opening the file to read data from
   if (strlen(src)){
      srcfile = fopen(src, "r");
      if (srcfile == NULL) {
         fprintf(stderr, "\nError file could not be opened\n");
         exit(1);
      }
   }
   int filesize = 0;
   int cnt = 1;

   // read, encode and send packets unlit EOF from stdin/src file
   while (true){
      if (cnt > 65534){
         // counter reset to avoid overflow
         cnt = 1;
      }
      char bytes[20];
      memset(bytes, 0, 20);
      int bytes_read;
      // read data
      if (srcfile == NULL){
         bytes_read = fread(bytes, 1, 20, stdin);
      }
      else{
         bytes_read = fread(bytes, 1, 20, srcfile);
      }
      if (bytes_read == 0) {
         // end of the file
         break;
      }
      filesize += bytes_read;
      char encoded[40];
      memset(encoded, 0 , 40);
      // encoding data read
      encody_bytes_to_base16(bytes, bytes_read, encoded);
      
      // setting qname for current packet
      char *qname = (char*)&buffer + sizeof(struct dns_packet);
      qname[0] = bytes_read * 2;
      memcpy(qname + 1, encoded, bytes_read*2);
      memcpy(qname + 1 + bytes_read*2, tmp_qname, strlen(tmp_qname) + 1);
      
      chunkid++;
      dns_sender__on_chunk_encoded(dst, chunkid, qname);
      
      struct dns_end packet_end;
      dns->id = htons(cnt);
      packet_end.qtype = htons(1);
      packet_end.qclass = htons(1);
      memcpy(qname + strlen(qname) + 1, &packet_end, sizeof(struct dns_end));
      // sending dns packet with encoded data
      if (sendto(sockfd, (char*)buffer, sizeof(struct dns_packet) + strlen(qname) + 1 + sizeof(struct dns_end), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
         printf("Failed to send query to upstream DNS server\n");
         return 1;
      }
      dns_sender__on_chunk_sent(&upstream_dns_addr, dst, chunkid, qname[0]);

      // giving server time to process
      usleep(1500);
      cnt++;
   }
   // close file if opened
   if (srcfile != NULL){
      fclose(srcfile);
   }

   // setting last packet 
   char* closing = "close";
   dns->id = htons(cnt);
   qname[0] = strlen(closing);
   memcpy(qname + 1, closing, strlen(closing));
   memcpy(qname + 1 + strlen(closing), tmp_qname, strlen(tmp_qname) + 1);
   chunkid++;
   
   packet_end.qtype = htons(1);
   packet_end.qclass = htons(1);

   memcpy(qname + strlen(qname) + 1, &packet_end, sizeof(struct dns_end));

   // sending last packet to indicate end of the connection

   if (sendto(sockfd, (char*)buffer, sizeof(struct dns_packet) + strlen(qname) + 1 + sizeof(struct dns_end), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
      printf("Failed to send query to upstream DNS server\n");
      return 1;
   }
   dns_sender__on_transfer_completed(dst, filesize); 
   
   return 0;
} 