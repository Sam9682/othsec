#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen
#include<time.h>    //strlen
 
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/ip6.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
 
int ProcessPacket(unsigned char * , int, unsigned char *, int);
char * print_ip_header(unsigned char * , int, unsigned char *);
char * print_ip6_header(unsigned char * , int, unsigned char *);
unsigned short print_ethernet_header(unsigned char *, int);
int print_tcp_packet(unsigned char * , int, unsigned char *);
int print_udp_packet(unsigned char * , int, unsigned char *);
int print_icmp_packet(unsigned char * , int, unsigned char *);
void PrintData (unsigned char * , int);
 
FILE *logfile;
struct sockaddr_in source, dest;
struct sockaddr_in6 source6, dest6;
int tcp=0, udp=0, icmp=0, others=0, igmp=0, total=0, i, j; 
unsigned short g_protocol;
char SzSource[INET6_ADDRSTRLEN], SzDest[INET6_ADDRSTRLEN];


//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
int sniffer( int filter_trafic)
{
    int saddr_size , data_size, to_print;
    struct sockaddr saddr;
    saddr_size = sizeof saddr;
    unsigned char *g_buffer = (unsigned char *) malloc(65536); //Its Big!
    unsigned char *g_buffer_output = (unsigned char *) malloc(1024); //Its not Big!
     
    int sock_raw = socket( AF_PACKET , SOCK_RAW , htons(ETH_P_ALL)) ;
    //setsockopt(sock_raw , SOL_SOCKET , SO_BINDTODEVICE , "eth0" , strlen("eth0")+ 1 );
     
    if(sock_raw < 0)
    {
        //Print the error with proper message
        perror("Socket Error");
        return 1;
    }
    while(1)
    {
        //Receive a packet
        data_size = recvfrom(sock_raw , g_buffer , 65536 , 0 , &saddr , (socklen_t*)&saddr_size);
        if(data_size <0 )
        {
            printf("Recvfrom error , failed to get packets\n");
            return -1;
        }
	else
        if(data_size >0 )
        {
		to_print = 1; 
		//Now process the packet
		to_print = ProcessPacket(g_buffer , data_size, g_buffer_output, filter_trafic);

		if (to_print) printf("%s\n", g_buffer_output);
		memset(g_buffer_output, 0, 255);
	}
 
    }
    close(sock_raw);
    return 0;
}
 

//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
int ProcessPacket(unsigned char* buffer, int size, unsigned char* buffer_out, int filter_trafic)
{
//Get the IP Header part of this packet , excluding the ethernet header
struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
struct ip6_hdr *iph6 = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));

	char *l_buffer = buffer;
	++total;
    
	g_protocol = print_ethernet_header(buffer, size);
		
	if ( g_protocol == ETH_P_IP)
	{
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;
	
		//"(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4))                    
		if ( filter_trafic && !strncmp(inet_ntoa(source.sin_addr),"127",3) && (!strncmp(inet_ntoa(dest.sin_addr),"127",3)) )
		{
			return 0;
		}
		if ( filter_trafic && !strncmp(inet_ntoa(source.sin_addr),"169.254",7) && (!strncmp(inet_ntoa(dest.sin_addr),"169.254",7)) )
		{
			return 0;
		}
		if ( filter_trafic && !strncmp(inet_ntoa(source.sin_addr),"192.168",7) && (!strncmp(inet_ntoa(dest.sin_addr),"192.168",7)) )
		{
			return 0;
		}
		if ( filter_trafic && !strncmp(inet_ntoa(source.sin_addr),"224",3) && (!strncmp(inet_ntoa(dest.sin_addr),"224",3)) )
		{
			return 0;
		}
		
		switch (iph->protocol) //Check the Protocol and do accordingly...
		{
			case 1:  //ICMP Protocol
				++icmp;
				return print_icmp_packet(l_buffer , size, buffer_out);
				break;

			case 2:  //IGMP Protocol
				++igmp;
				break;

			case 6:  //TCP Protocol
				++tcp;
				return print_tcp_packet(l_buffer , size, buffer_out);
				break;

			case 17: //UDP Protocol
				++udp;
				return print_udp_packet(l_buffer , size, buffer_out);
				break;

			default: //Some Other Protocol like ARP etc.
				++others;
				break;
		}
	}
	else
	if ( g_protocol == ETH_P_IPV6)
	{
		
		memset(&source6, 0, sizeof(source6));
		memcpy(&source6.sin6_addr.s6_addr, &iph6->ip6_src, sizeof(source6.sin6_addr.s6_addr));
		inet_ntop(AF_INET6, &source6.sin6_addr, SzSource, INET6_ADDRSTRLEN);

		memset(&dest6, 0, sizeof(dest6));
		memcpy(&dest6.sin6_addr.s6_addr, &iph6->ip6_dst, sizeof(dest6.sin6_addr.s6_addr));
		inet_ntop(AF_INET6, &dest6.sin6_addr, SzDest, INET6_ADDRSTRLEN);
	
		//"(ip)", "and", "(not", "(broadcast", "or", "multicast)", "and", "not", "(port", "514)", "and", "not", "(src", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4)", "and", "dst", "net", "(10", "or", "127", "or", "169.254", "or", "192.168", "or", "172.16/12", "or", "224.0.0.0/4))                    
		if ( filter_trafic && !strncmp(SzSource,"::1",3) && (!strncmp(SzDest,"::1",3)) )
		{
			return 0;
		}
		
		switch (iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt) //Check the Protocol and do accordingly...
		{
			case 1:  //ICMP Protocol
				++icmp;
				return print_icmp_packet(l_buffer , size, buffer_out);
				break;

			case 2:  //IGMP Protocol
				++igmp;
				break;

			case 6:  //TCP Protocol
				++tcp;
				return print_tcp_packet(l_buffer , size, buffer_out);
				break;

			case 17: //UDP Protocol
				++udp;
				return print_udp_packet(l_buffer , size, buffer_out);
				break;

			default: //Some Other Protocol like ARP etc.
				++others;
				break;
		}
	}
	else
	if (g_protocol == ETH_P_ARP)
	{
	}
	
return 0;
}


//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
unsigned short print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    // ETHER
    //Buffer_out += sprintf(Buffer_out , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5]);							// Dest Port
    //Buffer_out += sprintf(Buffer_out , "%.2X-%.2X-%.2X-%.2X-%.2X-%.2X ", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5]);	// Source Port
    //Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)eth->h_proto);							// Source Port
	
	return ntohs((uint16_t)eth->h_proto);
}


//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
char * print_ip6_header(unsigned char* Buffer, int Size, unsigned char* Buffer_out)
{
    time_t now_datetime = time(NULL);
    unsigned short iphdrlen;
    struct ip6_hdr *iph = (struct ip6_hdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen = sizeof( struct ip6_hdr);
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
           
    // TIMESTAMP
    Buffer_out += sprintf(Buffer_out , "%ld ", now_datetime);						// datetime

    // IP
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ip6_vfc);					// IP Version
    Buffer_out += sprintf(Buffer_out , "%u ", (uint32_t)iph->ip6_flow);					// Flow
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ip6_plen);					// IP Header Length
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ip6_nxt);					// Next Header
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ip6_hlim);					// Limit
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ip6_hops);					// Hops
    Buffer_out += sprintf(Buffer_out , "%s ", SzSource);						// Source IP
    Buffer_out += sprintf(Buffer_out , "%s ", SzDest);							// Destination IP

    return Buffer_out;
}


//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
char * print_ip_header(unsigned char* Buffer, int Size, unsigned char* Buffer_out)
{
    time_t now_datetime = time(NULL);
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen = sizeof(struct iphdr);
           
    // TIMESTAMP
    Buffer_out += sprintf(Buffer_out , "%ld ", now_datetime);						// datetime

    // IP
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->version);					// IP Version
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iphdrlen);					// IP Header Length
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->tos);					// Type Of Service
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->tot_len);						// IP Total Length
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->id);					// Identification
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->ttl);					// TTL
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)iph->protocol);					// Protocol
    //Buffer_out += sprintf(Buffer_out , "%s ", "TCP");							// Protocol
    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)ntohs(iph->check));				// Checksum
    Buffer_out += sprintf(Buffer_out , "%s ", inet_ntoa(source.sin_addr));				// Source IP
    Buffer_out += sprintf(Buffer_out , "%s ", inet_ntoa(dest.sin_addr));				// Destination IP
	
	return Buffer_out;
}
 

//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
int print_tcp_packet(unsigned char* Buffer, int Size, unsigned char* Buffer_out)
{
	unsigned short iphdrlen;
	if (g_protocol == ETH_P_IP)
	{
    		struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	    	iphdrlen = iph->ihl*4;
	    	//iphdrlen = sizeof(struct iphdr);
	}
	else
	if (g_protocol == ETH_P_IPV6)
	{
    		struct ip6_hdr *iph = (struct ip6_hdr *)(Buffer  + sizeof(struct ethhdr) );
	    	iphdrlen = sizeof(struct ip6_hdr);
	}
	
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

	if (g_protocol == ETH_P_IPV6)
	{
	    Buffer_out = print_ip6_header(Buffer, Size, Buffer_out);
	}
	else
	if (g_protocol == ETH_P_IP)
	{
	    Buffer_out = print_ip_header(Buffer, Size, Buffer_out);
	}
		
	// TCP
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(tcph->source));					// Source Port
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(tcph->dest));					// Destination Port
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(tcph->seq));					// Sequence Number
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohl(tcph->ack_seq));					// Acknowledge Number
	    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)tcph->doff*4);					// Header Length
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->urg)?'U':'-');					// Urgent Flag
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->ack)?'A':'-');					// Acknowledgement Flag
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->psh)?'P':'-');					// Push Flag
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->rst)?'R':'-');					// Reset Flag
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->syn)?'S':'-');					// Synchronise Flag
	    Buffer_out += sprintf(Buffer_out , "%c ", (tcph->fin)?'F':'-');					// Finish Flag
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(tcph->window));					// Window
	    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(tcph->check));					// Checksum
	    Buffer_out += sprintf(Buffer_out , "%u ", (uint16_t)tcph->urg_ptr);					// Urgent Pointer

    // DATA
    // PrintData(Buffer + header_size , Size - header_size );
   		
return 1;
}
 

//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
int print_udp_packet(unsigned char *Buffer , int Size, unsigned char* Buffer_out)
{
    unsigned short iphdrlen;
	if (g_protocol == ETH_P_IP)
	{
    	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	    iphdrlen = iph->ihl*4;
	}
	else
	{
    	struct ip6_hdr *iph = (struct ip6_hdr *)(Buffer  + sizeof(struct ethhdr) );
	    iphdrlen = sizeof(struct ip6_hdr);
	}    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	Buffer_out = print_ip_header(Buffer, Size, Buffer_out);
     
    // UDP
    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(udph->source));							// Source Port
    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(udph->dest));							// Destination Port
    Buffer_out += sprintf(Buffer_out , "%u ", ntohs(udph->len));							// UDP Length
    Buffer_out += sprintf(Buffer_out , "%u ", ntohl(udph->check));							// UDP Checksum
	
return 1;     
}
 

//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
int print_icmp_packet(unsigned char* Buffer , int Size, unsigned char* Buffer_out)
{
    unsigned short iphdrlen;
	if (g_protocol == ETH_P_IP)
	{
    	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
	    iphdrlen = iph->ihl*4;
	}
	else
	{
    	struct ip6_hdr *iph = (struct ip6_hdr *)(Buffer  + sizeof(struct ethhdr) );
	    iphdrlen = sizeof(struct ip6_hdr);
	}    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;
     
	Buffer_out = print_ip_header(Buffer, Size, Buffer_out);

	// ICMP
    Buffer_out += sprintf(Buffer_out , "%d ", (unsigned int)icmph->type);					// Type
    if((unsigned int)(icmph->type) == 11)
    {
		Buffer += sprintf(Buffer_out , "%s ", "(TTL Expired)");								// TTL
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
		Buffer_out += sprintf(Buffer_out , "%s ", "(ICMP Echo Reply)");						// TTL
    }
    Buffer_out += sprintf(Buffer_out , "%d ", (unsigned int)icmph->code);					// Code
    Buffer_out += sprintf(Buffer_out , "%d ", ntohs(icmph->checksum));						// Checksum
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
          
    //Move the pointer ahead and reduce the size of string
    //PrintData(Buffer + header_size , (Size - header_size) );
	
return 1;
}
 

//-------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------
void PrintData (unsigned char* data , int Size)
{
    int i , j;
    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[j]); //if its a number or alphabet
                 
                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");
             
            for(j=i-i%16 ; j<=i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) 
                {
                  fprintf(logfile , "%c",(unsigned char)data[j]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
}

//int main()
//{
// printf("Testing sniffer\n");
// sniffer(1);
//}
