

#include "../header/pcapmodu.h"
#include "../header/pcapcap.h"
   
u_short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}
// end in_cksum function .

void sendraw(const u_char* pre_packet, int mode)
{
      const MAC *ethernet;  /* The ethernet header [1] */

      u_char packet[1024];
        int raw_socket, on = 1;
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        int port = 80;
      u_char *payload = NULL ;
        int pre_payload_size = 0 ;
      int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;

      raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
      if (raw_socket == -1)
      {
         puts("Socket not created");
         return;
      }

      if (setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) == -1)
      {
         puts("setsockopt() error");
         return;
      }
      
      ethernet = (MAC*)(pre_packet);

        // TCP, IP 헤더 초기화
        iphdr = (struct iphdr *)(packet) ;
        memset( iphdr, 0, SIZE_MIN_IP );
        tcphdr = (struct tcphdr *)(packet + SIZE_MIN_IP);
        memset( tcphdr, 0, SIZE_MIN_TCP );

        // TCP 헤더 제작
        tcphdr->source = htons( 777 );
        tcphdr->dest = htons( port );
        tcphdr->seq = htonl( 92929292 );
        tcphdr->ack_seq = htonl( 12121212 );

      source_address.s_addr = ((struct iphdr *)(pre_packet + SIZE_ETHERNET))->daddr ;    // twist s and d address
      dest_address.s_addr = ((struct iphdr *)(pre_packet + SIZE_ETHERNET))->saddr ;      // for return response
      iphdr->id = ((struct iphdr *)(pre_packet + SIZE_ETHERNET))->id ;
      
      int pre_tcp_header_size = 0;

      pre_tcp_header_size = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->doff ;
      pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + SIZE_ETHERNET))->tot_len ) - ( SIZE_MIN_IP + pre_tcp_header_size * 4 );

      tcphdr->source = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->dest ;      // twist s and d port
      tcphdr->dest = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->source ;      // for return response
      tcphdr->seq = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->ack_seq ;
      tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->seq  + htonl(pre_payload_size - SIZE_MIN_IP);
      tcphdr->window = ((struct tcphdr *)(pre_packet + SIZE_ETHERNET + SIZE_MIN_IP))->window ;

        tcphdr->doff = 5;
        tcphdr->ack = 1;
        tcphdr->psh = 1;
        tcphdr->fin = 1;

        // 가상 헤더 생성.
        pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
        pseudo_header->saddr = source_address.s_addr;
        pseudo_header->daddr = dest_address.s_addr;
        pseudo_header->useless = (u_int8_t) 0;
        pseudo_header->protocol = IPPROTO_TCP;

      char packet_data[512] = "HTTP/1.1 200 OK\x0d\x0a"
                     "Content-Length: 512\x0d\x0a"
                     "Content-Type: text/html"
                     "\x0d\x0a\x0d\x0a"
                     "<html>\r\n"
                     "<head>\r\n"
                     "<meta http-equiv=\"Refresh\" content=\"0; URL=http://localhost:8080/\">\r\n"
                     "</head>\r\n"
                     "</html>";

      // write post_payload ( redirecting data 2 )
      //post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
      post_payload_size = strlen(packet_data) + SIZE_MIN_IP + SIZE_MIN_TCP;   // Content-Length: header is changed so post_payload_size is increased.
        //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
      memcpy ( (char*)packet + SIZE_MIN_IP + SIZE_MIN_TCP, packet_data, post_payload_size) ;
                
      pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

        tcphdr->check = in_cksum( (u_short *)pseudo_header,
        sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

        iphdr->version = 4;
        iphdr->ihl = 5;
        iphdr->protocol = IPPROTO_TCP;
        //iphdr->tot_len = 40;
        iphdr->tot_len = htons(SIZE_MIN_IP + SIZE_MIN_TCP + post_payload_size);

      iphdr->id = ((struct iphdr *)(pre_packet + SIZE_ETHERNET))->id + htons(1);
      memset( (char*)iphdr + 6 ,  0x40  , 1 );
            
        iphdr->ttl = 60;
        iphdr->saddr = source_address.s_addr;
        iphdr->daddr = dest_address.s_addr;
        iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

        address.sin_family = AF_INET;
      address.sin_addr.s_addr = dest_address.s_addr;
      address.sin_port = tcphdr->dest ;

      payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );
      size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

      if ( mode == 1 )
        {
         sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;

         if ( sendto_result != ntohs(iphdr->tot_len) )
         {
            puts("sendto() error");
            return;
         }
      }

      puts("\t[Packet After Change]");
      print_payload(packet, size_payload);

        close( raw_socket );
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

   int i;
   int gap;
   const u_char *ch;

   /* offset */
   printf("%05d   ", offset);

   /* hex */
   ch = payload;

   for(i = 0; i < len; i++) {
      printf("%02x ", *ch);
      ch++;
      /* print extra space after 8th byte for visual aid */
      if (i == 7)
         printf(" ");
   }
   /* print space to handle line less than 8 bytes */
   if (len < 8)
      printf(" ");

   /* fill hex gap with spaces if not full line */
   if (len < 16) {
      gap = 16 - len;
      for (i = 0; i < gap; i++) {
         printf("   ");
      }
   }
   printf("   ");

   /* ascii (if printable) */
   ch = payload;
   for(i = 0; i < len; i++) {
      if (isprint(*ch))
         printf("%c", *ch);
      else
         printf(".");
      ch++;
   }

   printf("\n");

    return;
}

void
print_payload(const u_char *payload, int len)
{

   int len_rem = len;
   int line_width = 16;         /* number of bytes per line */
   int line_len;
   int offset = 0;               /* zero-based offset counter */
   const u_char *ch = payload;

   if (len <= 0)
      return;

   /* data fits on one line */
   if (len <= line_width) {
      print_hex_ascii_line(ch, len, offset);
      return;
   }

   /* data spans multiple lines */
   for ( ;; ) {
      printf("\t");
      /* compute current line length */
      line_len = line_width % len_rem;
      /* print line */
      print_hex_ascii_line(ch, line_len, offset);
      /* compute total remaining */
      len_rem = len_rem - line_len;
      /* shift pointer to remaining bytes to print */
      ch = ch + line_len;
      /* add offset */
      offset = offset + line_width;
      /* check if we have line width chars or less */
      if (len_rem <= line_width) {
         /* print last line and get out */
         printf("\t");
         print_hex_ascii_line(ch, len_rem, offset);
         break;
      }
   }

   return;
}