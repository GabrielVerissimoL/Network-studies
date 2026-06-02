#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <linux/icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#define BUFSIZE 2000 //Buffer for reading TUN/TAP must be >= 1500

int tun_open() {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun"; // Linux TUN device path
    
    // Open '/dev/net/tun'
    if( (fd = open(clonedev, O_RDWR)) < 0 ) { // O_RDWR means Open for Read and Write
        perror("Opening /dev/net/tun");
        return fd;
    }    

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;


    //TUNSETIFF requires a ifreq struct as the third parameter
    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) { //TUNSETIFF used to create the virtual interface
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    return fd;
}

/*
Checksum verifies the integrity of the packet
*/
uint16_t checksum(unsigned char *buf, int len) {
    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)buf; // ptr now is an array of words

    while (len > 1) {
        sum += *ptr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(unsigned char *)ptr;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;  
}

int main() {
    char buffer[BUFSIZE];
    int Nbytes = 0;

    int fd = tun_open();

    while (1) {
        Nbytes = read(fd, buffer, sizeof(buffer));
        if (Nbytes < 0) {
            perror("read(fd)");
        }

        //Cast buffer to struct iphdr
        struct iphdr *iph = (struct iphdr *)buffer;

        // Get the ip header size from words to bytes
        size_t ip_header_len = iph->ihl * 4;

        // Convert binary ip addresses to readable strings
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);

        //TODO: Colocar uma porta personalizada
        // Blocking the 10.0.0.50 port specifically 
        if (iph->daddr == inet_addr("10.0.0.50")) {
            printf("[BLOCK] 10.0.0.50 bloqueada!\n");
            continue;
        }

        if (iph->protocol == IPPROTO_ICMP) {
            if (Nbytes < ip_header_len + sizeof(struct icmphdr))
                continue;

            struct icmphdr *icmph = (struct icmphdr *) (buffer + ip_header_len);

            if (icmph->type == 8) {
                
                printf("[ICMP] echo request de %s para %s\n", src_ip, dst_ip);

                char buffer_response[4096];
                
                struct iphdr *iph_response = (struct iphdr *)buffer_response;
                iph_response->version = 4;
                iph_response->ihl = 5;
                iph_response->protocol = IPPROTO_ICMP;
                iph_response->saddr = iph->daddr;
                iph_response->daddr = iph->saddr;
                iph_response->ttl = 64;
                iph_response->tot_len = htons(ip_header_len + sizeof(struct icmphdr));
                iph_response->check = 0;
                iph_response->check = checksum((unsigned char *)iph_response, ip_header_len);

                struct icmphdr *icmph_response = (struct icmphdr *) (buffer_response + ip_header_len);
                icmph_response->type = 0;
                icmph_response->code = 0;
                icmph_response->un.echo.id = icmph->un.echo.id;
                icmph_response->un.echo.sequence = icmph->un.echo.sequence;
                icmph_response->checksum = 0;
                icmph_response->checksum = checksum((unsigned char *)icmph_response, sizeof(struct icmphdr));

                write(fd, buffer_response, ip_header_len+ sizeof(struct icmphdr));
            }
        }

        if(iph->protocol == IPPROTO_TCP) {
            // list of blocked words
            char *Blocked_Words[] = {"Calculo", "DM"};

            if(Nbytes < ip_header_len + sizeof(struct tcphdr))
                continue;

            // place the pointer at the start of the TCP Header
            struct tcphdr *tcph = (struct tcphdr *) (buffer + ip_header_len);

            // doff contains the TCP header size in 32-bit words
            size_t tcp_header_len = tcph->doff * 4;

            //Pointer to the start of the TCP Payload
            char *TCP_PAYLOAD = (buffer + ip_header_len + tcp_header_len);

            // Filter for blocked words
            char *resultado;
            int blocked_TCP = 0; // flag para palavra proibida
            int total = sizeof(Blocked_Words) / sizeof(Blocked_Words[0]);
            for (int i = 0; i < total; i++) {
                resultado = strstr(TCP_PAYLOAD, Blocked_Words[i]); // Needle Haystack
                if (resultado != NULL) {
                    blocked_TCP = 1;
                    break;
                }
            }

            if (blocked_TCP) {
                printf("❗Blocked Word Found\n");
                continue;
            }
        }

        //UDP header is fixed at 8 bytes!
        //char *strstr(const char *string1, const char *string2);
        if(iph->protocol == IPPROTO_UDP) {
            //list of blocked words
            char *Blocked_Words[] = {"Calculo", "DM"};

            if(Nbytes < ip_header_len + sizeof(struct udphdr))
                continue;
        
            //Pointer to the start of the UDP payload 
            char *UDP_Payload_str = buffer + ip_header_len + sizeof(struct udphdr); 

            //Filter for blocked words
            char *resultado;
            int blocked_UDP = 0; //flag para palavra proibida
            int total = sizeof(Blocked_Words) / sizeof(Blocked_Words[0]);
            for (int i = 0; i < total; i++) {
                resultado = strstr(UDP_Payload_str, Blocked_Words[i]);
                if (resultado != NULL) {
                    blocked_UDP = 1;
                    break;
                }
            }

            if (blocked_UDP) {
                printf("❗Blocked Word Found\n");
                continue;
            }
        }


        printf("Protocolo: %d | Ip de origem: %s | Ip de destino: %s\n", iph->protocol, src_ip, dst_ip);
        printf("Número de bytes lido foi de %d\n", Nbytes);
    }

    return 0;
}
