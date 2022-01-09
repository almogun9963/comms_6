#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <linux/tcp.h>
#include <ctype.h>
#include <string.h> 
#include <fcntl.h>
#include <unistd.h>
#define ETHER_ADDR_LEN 6
#define EXIT_FAILURE 1
#define MTU 1500

struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct ipheader
{

    unsigned char iph_ihl : 4, iph_ver : 4;
    unsigned char iph_tos;
    unsigned short int iph_len;
    unsigned short int iph_ident;
    unsigned short int iph_flag : 3, iph_offset : 13;
    unsigned char iph_ttl;
    unsigned char iph_protocol;
    unsigned short int iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

struct icmpheader
{
    unsigned char icmp_type;
    unsigned char icmp_code;
    unsigned short int icmp_chksum;
    unsigned short int icmp_id;
    unsigned short int icmp_seq;
};

void spoof_RawSocket(struct ipheader* ip)
{
    struct sockaddr_in dest_addr;
    int enable = 1;

    // Raw Socket.
    int sock = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);

    // enable IP_HDRINCL.
    int set = setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));

    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip->iph_destip;

    sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));

    close(sock);
}

// Compute checksum.
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

// spoof ICMP, src ip set to 1.2.3.4
int main()
{
    char buffer[MTU];

    memset(buffer, 0, MTU);

    struct icmpheader *icmp = (struct icmpheader*)(buffer + sizeof(struct ipheader));

    icmp->icmp_type = 8;
    icmp->icmp_chksum = 0;
    icmp->icmp_chksum = calculate_checksum((unsigned short*)icmp, sizeof(struct icmpheader));

    struct ipheader *ip = (struct ipheader*)buffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 99;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
    ip->iph_destip.s_addr = inet_addr("192.168.1.26");
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

    //send fake packet
    spoof_RawSocket(ip);

    return 0;

}
