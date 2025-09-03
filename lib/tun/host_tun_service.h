#ifndef HOST_TUN_SERVICE_H
#define HOST_TUN_SERVICE_H

// Function prototypes for host_tun_service.c
int host_tun_open(const char *ifname, int is_tap, int *tun_fd);
int host_tun_close(int tun_fd);

#endif // HOST_TUN_SERVICE_H
