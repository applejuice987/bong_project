

#include "../header/pcapmodu.h"
#include "../header/pcapcap.h"
	
unsigned short in_cksum(u_short *addr, int len)
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

int sendraw( u_char* pre_packet, int mode)
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int loop1=0;
        int loop2=0;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_vlan = 0 ;
		int size_vlan_apply = 0 ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
	    int rc = 0 ;
	    //struct ifreq ifr ;
		char * if_bind ;
		int if_bind_len = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		char* ipaddr_str_ptr ;

		int warning_page = 1 ;
		int vlan_tag_disabled = 0 ;

		int ret = 0 ;


		//char if_bind_global[] = "enp0s3" ;
		char if_bind_global[] = "lo" ;
		//int if_bind_global_len = 6 ;
		int if_bind_global_len = 2 ;


		#ifdef SUPPORT_OUTPUT
		print_chars('\t',6);
		printf( "\n[raw socket sendto]\t[start]\n\n" );

		if (size_payload > 0 || 1) {
			print_chars('\t',6);
			printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);
			print_payload_right(pre_packet, 100);
		}
		//m-debug
		printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
		#endif

        for( port=80; port<81; port++ ) {
			#ifdef SUPPORT_OUTPUT
			print_chars('\t',6);
			printf("onetime\n");
			#endif
			// raw socket 생성
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				return -2;
			}

			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

			if ( if_bind_global != NULL ) {
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );

				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
				}
				#endif

			}

			ethernet = (struct sniff_ethernet*)(pre_packet);
			if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("vlan packet\n");
				#endif
				size_vlan = 4;
				memcpy(packet, pre_packet, size_vlan);
			} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("normal packet\n");
				#endif
				size_vlan = 0;
			} else {
				fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
			}

			vlan_tag_disabled = 1 ;
			if ( vlan_tag_disabled == 1 ) {
				size_vlan_apply = 0 ;
				memset (packet, 0x00, 4) ;
			} else {
				size_vlan_apply = size_vlan ;
			}
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

				#ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
				#endif

				source_address.s_addr = 
				((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
				// twist s and d address
				dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;		// for return response
				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
				int pre_tcp_header_size = 0;
				char pre_tcp_header_size_char = 0x0;
				pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
				pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

				tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;		// twist s and d port
				tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;		// for return response
				tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
				tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
				tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

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
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				// m-debug
				printf("DEBUG: &packet == \t\t %p \n" , &packet);
				printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
				printf("DEBUG: iphdr == \t\t\t %p \n" , iphdr);
				printf("DEBUG: tcphdr == \t\t\t %p \n" , tcphdr);
				#endif

				#ifdef SUPPORT_OUTPUT
                strcpy( (char*)packet + 40, "HAHAHAHAHOHOHOHO\x0" );
				#endif

				// choose output content
				warning_page = 5;
				if ( warning_page == 5 ){
					// write post_payload ( redirecting data 2 )
					//post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
					post_payload_size = 230 + 65  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
					memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
							"Content-Length: 230\x0d\x0a"
							"Content-Type: text/html"
							"\x0d\x0a\x0d\x0a"
							"<html>\r\n"
							"<head>\r\n"
							"<meta http-equiv=\"Refresh\" content=\"0; URL=http://localhost:8080/\">\r\n"

							"</head>\r\n"
							"</html>", post_payload_size ) ;
                }
				pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				//m-debug
				printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
				#endif

				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);
				
				memset( (char*)iphdr + 6 ,  0x40  , 1 );
				
                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

				address.sin_port = tcphdr->dest ;
				address.sin_addr.s_addr = dest_address.s_addr;

				prt_sendto_payload = 0;
				#ifdef SUPPORT_OUTPUT
				prt_sendto_payload = 1 ;
				#endif

				if( prt_sendto_payload == 1 ) {

				print_chars('\t',6);
				printf("sendto Packet data :\n");

				print_chars('\t',6);
				printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("   Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("   Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("   Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("   Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("   Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("   Protocol: unknown\n");
						//free(packet_dmp);
						return -2;
				}

				print_chars('\t',6);
				printf("   Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("   Dst port: %d\n", ntohs(tcphdr->dest));

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

				printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
								sizeof(struct iphdr) , tcphdr->doff * 4);

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, 40);
				}

				if (size_payload > 0) {
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					print_payload_right(payload, size_payload);
				}
			} // end -- if -- prt_sendto_payload = 1 ;
				if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
					if ( sendto_result != ntohs(iphdr->tot_len) ) {
						fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
						ret = -10 ;
					} else {
						ret = 1 ;
					}
		        } // end if(mode)
                //} // end for loop

				if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
							*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
							*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
							source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
				}
                close( raw_socket );
                
        } // end for loop
		#ifdef SUPPORT_OUTPUT
        printf( "\n[sendraw] end .. \n\n" );
		#endif
		//return 0;
		return ret ;
}
// end sendraw function .

int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
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
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

	/* print 10 tabs for output to right area	*/
	for ( i = 0 ; i < tabs_cnt ; i++ ) {
		printf("\t");
	}

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

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
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
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line_right(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line_right(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line_right(ch, len_rem, offset);
			break;
		}
		//m-debug
		if ( offset > 600 ) {
			print_chars('\t',6);
			printf("INFO: ..........    payload too long (print_payload_right func) \n");
			break;
		}
	}

    return;
}
