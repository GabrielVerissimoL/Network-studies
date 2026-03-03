#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

// Source MAC
char* get_source_mac(struct ethhdr *eth) {
    static char source[18];
    sprintf(source, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    return source;
}

// Destination MAC
char* get_dest_mac(struct ethhdr *eth) {
    static char dest[18];
    sprintf(dest, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    return dest;
}


int main()
{
    int sock;
    uint8_t buffer[65536];
  
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));


    if (sock < 0) {
        perror("Socket");
        return 1;
    }

    printf("Sniffer iniciado\n");

    while(1) {
        ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);

        if (n < 0) {
            perror("recvfrom failed");
            return 1;
        }

        if (n < sizeof(struct ethhdr)) {
            continue;
        }

        struct ethhdr *eth = (struct ethhdr *) buffer;
        uint16_t ethertype = ntohs(eth->h_proto);


        if (ethertype == 0x0800) {
            if (n < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
                continue;
            }

            struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            if (iph->version != 4) {
                continue;
            }

            if (iph->ihl < 5) {
                continue;
            }

            //IHL stands for words of 4 bytes, here we get the total amount of bytes for the IP
            size_t ip_header_len = iph->ihl * 4;

            if (n < sizeof(struct ethhdr) + ip_header_len) {
                continue;
            }

            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);

            printf("\nIPV4 | Version: %u | IHL: %u | Protocol: %u | Source: %s | Destination: %s | Header Length: %zu\n", iph->version, iph->ihl, iph->protocol, src_ip, dst_ip, ip_header_len);
        }

        printf("Received %03zd bytes | Source MAC: %s  ->  Destination MAC: %s | EtherType: %04x\n\n", n, get_source_mac(eth), get_dest_mac(eth), ethertype);

    }

    
    close(sock);
    return 0;
}