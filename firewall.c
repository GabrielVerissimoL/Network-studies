#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h> 
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


int firewall_decision(unsigned char *packet, int len) {

    // Pacote menor que cabeçalho IP mínimo (20 bytes) — não temos nada útil pra analisar
    if (len < sizeof(struct iphdr)) {
        return NF_ACCEPT;
    }

    // Interpreta os bytes brutos como cabeçalho IPv4
    struct iphdr *iph = (struct iphdr *) packet;

    // Sanidade: deve ser IPv4 e IHL válido (mínimo 5 palavras de 32 bits = 20 bytes)
    if (iph->version != 4 || iph->ihl < 5) {
        return NF_ACCEPT;
    }

    // IHL está em palavras de 32 bits — multiplica por 4 pra obter bytes
    size_t ip_header_len = iph->ihl * 4;

    // IHL vem do pacote (dado externo) — garante que não ultrapassa o buffer
    if (len < ip_header_len) {
        return NF_ACCEPT;
    }

    // Analisa apenas TCP — outros protocolos passam direto
    if (iph->protocol == IPPROTO_TCP) {

        // Garante que o buffer contém um cabeçalho TCP completo após o IP
        if (len < ip_header_len + sizeof(struct tcphdr)) {
            return NF_ACCEPT;
        }

        // Cabeçalho TCP começa logo após o cabeçalho IP
        struct tcphdr *tcph = (struct tcphdr *) (packet + ip_header_len);

        // ntohs: converte Big Endian (rede) para Little Endian (host)
        unsigned short src_port = ntohs(tcph->source);
        unsigned short dst_port = ntohs(tcph->dest);

        // Converte IPs binários para string legível
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->daddr), dst_ip, INET_ADDRSTRLEN);

        // Regra: bloqueia conexões de saída para porta 23 (Telnet)
        if (dst_port == 23) {
            printf("[BLOCK] TCP %s:%hu -> %s:%hu\n", src_ip, src_port, dst_ip, dst_port);
            return NF_DROP;
        }
    }

    // Política default: aceita tudo que não foi explicitamente bloqueado
    return NF_ACCEPT;
}


// Função chamada toda vez que chega um pacote novo
static int callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    struct nfqnl_msg_packet_hdr *ph;
    uint32_t id = 0;

    // Extrai o ID do pacote e converte de Network Byte Order para Host
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph)
        id = ntohl(ph->packet_id);

    // Extrai os bytes brutos do pacote
    unsigned char *packet;
    int len = nfq_get_payload(nfa, &packet);

    // Delega a decisão pra firewall_decision() e devolve o veredicto ao kernel
    return nfq_set_verdict(qh, id, firewall_decision(packet, len), 0, NULL);
}

int main()
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[4096];

    printf("Firewall iniciado\n");

    // 1. Abre a conexão com a biblioteca Netfilter
    h = nfq_open();
    if (!h) {
        perror("nfq_open");
        exit(1);
    }

    // 2. Desvincula qualquer configuração anterior (limpeza)
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        perror("nfq_unbind_pf");
    }

    // 3. Vincula o firewall para processar pacotes da família IPv4 (AF_INET)
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf");
        exit(1);
    }

    // 4. Cria a fila número 0. Pacotes enviados para 'NFQUEUE --queue-num 0' cairão aqui.
    qh = nfq_create_queue(h, 0, &callback, NULL);
    if (!qh) {
        perror("nfq_create_queue");
        exit(1);
    }

    // 5. Define que queremos copiar o pacote inteiro para o userspace (modo COPY_PACKET)
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode");
        exit(1);
    }

    // 6. Pega o File Descriptor para escutar os pacotes que o Kernel enviará
    fd = nfq_fd(h);

    // Loop infinito: recebe dados brutos do Netfilter e passa para a função callback tratar
    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0)
            nfq_handle_packet(h, buf, rv); // Chama o callback internamente
        else if (rv < 0) {
            if (errno == EINTR)
                continue;
            perror("recv");
        }
    }

    // Limpeza (raramente alcançado em firewalls que rodam para sempre)
    nfq_destroy_queue(qh);
    nfq_close(h);

    return 0;
}