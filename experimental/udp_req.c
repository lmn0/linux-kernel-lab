

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <resolv.h>
#include <time.h>


struct DNSheader
{
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

struct ETHheader
{
    unsigned char dest_mac[ETH_ALEN];
    unsigned char src_mac[ETH_ALEN];
    unsigned short eth_type;
};

struct DNS_HEADER {
    unsigned short id; // Identification number
    unsigned char rd :1; // Recursion desired
    unsigned char tc :1; // Truncated message
    unsigned char aa :1; // Authoritative answer
    unsigned char opcode :4; // Purpose of message
    unsigned char qr :1; // Query/response flag
    unsigned char rcode :4; // Response code
    unsigned char cd :1; // Checking disabled
    unsigned char ad :1; // Authenticated data
    unsigned char z :1; // Reserved
    unsigned char ra :1; // Recursion available
    unsigned short q_count; // Number of question entries
    unsigned short ans_count; // Number of answer entries
    unsigned short auth_count; // Number of authority entries
    unsigned short add_count; // Number of resource entries
};

struct DNS_QUESTION {
    //unsigned char *name; // Domain name
    unsigned short qtype; // Query type (e.g., A, MX, CNAME)
    unsigned short qclass; // Query class (e.g., IN for internet)
} ;




int _udpsocket = 0;
int _srcip = 0;
int _dnsip = 0;
int _sendinterval = 0;
int _querycount = 0;

unsigned short checksum(unsigned short *data, size_t len) {
  unsigned short sum = 0;
  for (size_t i = 0; i < len; i++) {
    sum += data[i];
  }
  return sum;
}

int  convert_domain(char *domain)
{
    char out[256];
    char *p = domain;
    char *pout = &out[0];
    while (*p)
    {
        int size = 0;
        char *pdomain = p;
        while (*pdomain && *pdomain != '.')
        {
            size++;
            pdomain++;
        }
        pout[0] = size;
        pout ++;
        strncpy(pout, p, size);
        pout += size;
        p = pdomain;
        if ('.' == *p)
        {
            p++;
        }
    }
    *(pout) = 0;
    memcpy(domain, &out[0], pout - &out[0] + 1);
    return pout - &out[0] + 1;
}

int build_datagram(char *datagram, unsigned int payload_size, uint32_t src_ip, uint32_t dst_ip, u_int16_t port)
{
    struct ip *ip_hdr = (struct ip *) datagram;
    struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof (struct ip));

    ip_hdr->ip_hl = 5; //header length
    ip_hdr->ip_v = 4; //version
    ip_hdr->ip_tos = 0; //tos
    ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;  //length
    ip_hdr->ip_id = 0; //id
    ip_hdr->ip_off = 0; //fragment offset
    ip_hdr->ip_ttl = 255; //ttl
    ip_hdr->ip_p = 17; //protocol
    ip_hdr->ip_sum = 0; //temp checksum
    ip_hdr->ip_src.s_addr = src_ip; //src ip - spoofed
    ip_hdr->ip_dst.s_addr = dst_ip; //dst ip

    udp_hdr->uh_sport = port; //src port - spoofed
    udp_hdr->uh_dport = htons(53); //dst port
    udp_hdr->uh_ulen = htons(sizeof(struct udphdr) + payload_size); //length
    udp_hdr->uh_sum = 0; //checksum - disabled

    ip_hdr->ip_sum = checksum((unsigned short *) datagram, ip_hdr->ip_len >> 1); //real checksum

    return ip_hdr->ip_len >> 1;
}



int main(int argc, char **argv)
{
	struct sockaddr_in dns_addr;
    int bytes_sent, bytes_received;
    int len = 0;
    char buffer_send[34];
    char buffer_recv[1500];
    char domain_name[256];
    
    int one = 1;
    const int *optval = &one;

    _udpsocket = socket(AF_INET, SOCK_DGRAM, 17); //socket(AF_INET, SOCK_DGRAM, 17);


    if (setsockopt(_udpsocket, SOL_SOCKET ,SO_REUSEADDR, optval, sizeof(one)))
    {
        printf("setsockopt()\n");
        close(_udpsocket);
        return -1;
    }

    _srcip = inet_addr(argv[1]);
    strcpy(domain_name,argv[2]);
    _dnsip = inet_addr(argv[3]);

    
    struct DNS_HEADER *dns_header = (struct DNS_HEADER *)(&buffer_send[0]);//sizeof(struct ip) + sizeof(struct udphdr)+1) ;
  
    char *dat = (char *)(&buffer_send[0] + sizeof(struct DNS_HEADER));



    dns_header->id = 1;//(unsigned short) htons(getpid());
    dns_header->qr = 0; //This is a query
    dns_header->opcode = 0; //This is a standard query
    dns_header->aa = 0; //Not Authoritative
    dns_header->tc = 0; //This message is not truncated
    dns_header->rd = 1; //Recursion Desired
    dns_header->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns_header->z = 0;
    dns_header->ad = 0;
    dns_header->cd = 0;
    dns_header->rcode = 0;
    dns_header->q_count = htons(1); //we have only 1 question
    dns_header->ans_count = 0;
    dns_header->auth_count = 0;
    dns_header->add_count = 0;



    len = convert_domain(domain_name);

    strcpy((char *)(dat),domain_name);

    struct DNS_QUESTION *dns_question = (struct DNS_QUESTION *)(&buffer_send[0] + sizeof(struct DNS_HEADER) + len + 1);

    //dns_question->name = (char *)malloc(len * sizeof(char));
    //strcpy(dns_question->name,domain_name);
    dns_question->qtype = 1;

    dns_question->qclass = 1;

    len += sizeof(struct DNS_HEADER) + sizeof(struct DNS_QUESTION) ;

    dns_addr.sin_family = PF_INET;
    dns_addr.sin_port = htons(53);
    dns_addr.sin_addr.s_addr = htonl((((((192 << 8) | 168) << 8) | 1) << 8) | 1);


    for (size_t i = 0; i < sizeof(buffer_send); ++i) {
        printf("%02x ", buffer_send[i]);
    }

    bytes_sent = sendto(_udpsocket, buffer_send, len, 0, (struct sockaddr *)&dns_addr, sizeof(dns_addr));

    printf("\n%d\n\nRecieving Bytes\n",bytes_sent);

    bytes_received = recvfrom(_udpsocket, buffer_recv, 1500, 0, (struct sockaddr *)&dns_addr,(socklen_t *) sizeof(dns_addr));

    for (size_t i = 0; i < sizeof(buffer_recv); ++i) {
        printf("%c", buffer_recv[i]);
    }
    printf("\n%d\n",bytes_received);

    char* data = (char*) (&buffer_recv[0]  + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct DNSheader));
    int s, bytes;


    struct udphdr *udp_hdr = (struct udphdr *)(&buffer_recv[0] + sizeof(struct ip));

    struct ip *ip_hdr = (struct ip *) &buffer_recv[0];

    unsigned int *strFirst;
    
    close(_udpsocket);
    return 0;
}

