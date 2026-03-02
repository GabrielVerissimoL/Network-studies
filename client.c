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

        struct ethhdr *eth = (struct ethhdr *) buffer;
        uint16_t ethertype = ntohs(eth->h_proto);

         if (n < sizeof(struct ethhdr)) {
            continue;
        }

        printf("Received %03zd bytes | Source MAC: %s  ->  Destination MAC: %s | EtherType: %04x\n", n, get_source_mac(eth), get_dest_mac(eth), ethertype);
    }

    

    return 0;
}