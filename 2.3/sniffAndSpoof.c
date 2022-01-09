#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <linux/tcp.h>
#include <ctype.h>
#include <string.h>
#define ETHER_ADDR_LEN 6
#define EXIT_FAILURE 1
#define MTU 1500
#include <fcntl.h>
#include <unistd.h>


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

    //enable IP_HDRINCL.
    int set = setsockopt(sock,IPPROTO_IP,IP_HDRINCL,&enable,sizeof(enable));
    
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = ip->iph_destip;
    sendto(sock,ip,ntohs(ip->iph_len),0,(struct sockaddr*)&dest_addr,sizeof(dest_addr));
    close(sock);
}

void forge_Packet(struct ipheader *ip)
{
    int header_length = ip->iph_ihl*4;
    const char buffer[MTU];
    // Copying the Packet
    bzero((char *)buffer,MTU);
    memcpy((char*)buffer,ip,ntohs(ip->iph_len));

    struct ipheader* fakeIP = (struct ipheader*)buffer;
    struct icmpheader* fakeICMP = (struct icmpheader*)(buffer + sizeof(header_length));
    // Swap Src and Dest ips for fake ip
    fakeIP->iph_sourceip = ip->iph_destip;
    fakeIP->iph_destip = ip->iph_sourceip;
    printf("%s", inet_ntoa(ip->iph_sourceip));
    printf("%s", inet_ntoa(ip->iph_destip));
    fakeIP->iph_ttl = 99;
    // ICMP reply - type 0
    fakeICMP->icmp_type = 0;

    spoof_RawSocket(fakeIP);

}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    {
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("-------------------------------------\n");
        printf("Source IP--------: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP---: %s\n", inet_ntoa(ip->iph_destip));
        printf("-------------------------------------\n");
        printf("-------------------------------------\n");
        //icmp packets
        forge_Packet(ip);
    }
}

int main()
{

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip proto \\icmp";
    bpf_u_int32 net;

    // Open pcap session
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

    // Compile Filter into the BPF
    pcap_compile(handle, &fp, filter_exp, 0, net);

    //Capture packets
    if (pcap_setfilter(handle, &fp) == -1)
    {
        pcap_perror(handle, "ERROR");
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}
