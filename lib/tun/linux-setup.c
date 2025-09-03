/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-tun.h"
#include <unistd.h>

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sock_domain

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>

// Define the proxy server details
#define PROXY_SERVER_IP "127.0.0.1" // Replace with your proxy server IP
#define PROXY_SERVER_PORT 12345     // Replace with your proxy server port

// Helper function to connect to proxy server
static int connect_to_proxy(void) {
  int sockfd;
  struct sockaddr_in proxy_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "socket() failed");
    return -1;
  }

  memset(&proxy_addr, 0, sizeof(proxy_addr));
  proxy_addr.sin_family = AF_INET;
  proxy_addr.sin_port = htons(PROXY_SERVER_PORT);

  if (inet_pton(AF_INET, PROXY_SERVER_IP, &proxy_addr.sin_addr) <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "Invalid proxy IP address");
    close(sockfd);
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "connect() to proxy failed");
    close(sockfd);
    return -1;
  }

  return sockfd;
}

// Modified ogs_tun_open
ogs_socket_t ogs_tun_open(char *ifname, int len, int is_tap) {
  ogs_socket_t fd = INVALID_SOCKET;
  int proxy_fd;
  char buffer[128];
  int rc;

  ogs_assert(ifname);

  // Connect to the proxy server
  proxy_fd = connect_to_proxy();
  if (proxy_fd < 0) {
    return INVALID_SOCKET;
  }

  // Send open request to proxy
  snprintf(buffer, sizeof(buffer), "OPEN %s %d\n", ifname, is_tap);
  rc = send(proxy_fd, buffer, strlen(buffer), 0);
  if (rc <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "send() failed");
    close(proxy_fd);
    return INVALID_SOCKET;
  }

  // Receive the virtual file descriptor
  rc = recv(proxy_fd, buffer, sizeof(buffer) - 1, 0);
  if (rc <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "recv() failed");
    close(proxy_fd);
    return INVALID_SOCKET;
  }

  buffer[rc] = '\0';
  fd = atoi(buffer); // The proxy returns a "virtual" file descriptor

  if (fd <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "Invalid fd from proxy");
    close(proxy_fd);
    return INVALID_SOCKET;
  }

  // Store the proxy_fd in a mapping table for use in read/write
  // (You can use a static table or a hash map for this purpose)

  return proxy_fd;
}

/**
 * Set the IP address for the TUN interface (currently a placeholder).
 */
int ogs_tun_set_ip(char *ifname, ogs_ipsubnet_t *gw, ogs_ipsubnet_t *sub) {
  // Placeholder for setting IP on TUN interface
  return OGS_OK;
}
