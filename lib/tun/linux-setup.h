#ifndef LINUX_SETUP_H
#define LINUX_SETUP_H

#include <stddef.h>

int connect_to_server(void);
int send_packet(int sockfd, const void *buf, size_t len);
int recv_packet(int sockfd, void *buf, size_t len);

#endif // LINUX_SETUP_H
