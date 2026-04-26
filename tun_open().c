#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <linux/if_tun.h>

int tun_open() {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun"; // Endereço do arquivo TUN no linux
    
    //Abrindo o '/dev/net/tun'
    if( (fd = open(clonedev, O_RDWR)) < 0 ) { // O_RDWR é uma constante que significa Open for Read and Write
        perror("Opening /dev/net/tun");
        return fd;
    }    

    //Limpa a struct ifreq
    memset(&ifr, 0, sizeof(ifr));

    //Setando as flags necessárias para continuar ( | combina duas flags em uma só)
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }


    
    
    
    
    
    return fd;

}
