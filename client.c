#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

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

        printf("Received %zd bytes | Source MAC %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", n, eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    }

    

    return 0;
}