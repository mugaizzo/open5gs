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

#include "ogs-core.h"
#include "ogs-tun.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/tun_service.sock"
#define BUFFER_SIZE 4096
#define COMMAND_BUFFER_SIZE 512
#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sock_domain

// Modified ogs_tun_read
ogs_pkbuf_t *ogs_tun_read(ogs_socket_t fd, ogs_pkbuf_pool_t *packet_pool) {
  ogs_pkbuf_t *recvbuf = NULL;
  char buffer[OGS_MAX_PKT_LEN + 64]; // Extra space for proxy headers
  int proxy_fd;                      // Retrieve proxy_fd from mapping table
  int n;

  ogs_assert(fd != INVALID_SOCKET);

  // Retrieve the proxy_fd associated with this fd
  proxy_fd = fd; // Assume fd is already mapped to proxy_fd
  //ogs_log_message(OGS_LOG_INFO, errno, "the fd is %d", fd);
  // Send read request to proxy
  snprintf(buffer, sizeof(buffer), "READ %d\n", fd);
  n = send(proxy_fd, buffer, strlen(buffer), 0);
  if (n <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "send() failed");
    return NULL;
  }

  // Receive the raw IPv4 packet from proxy
  n = recv(proxy_fd, buffer, sizeof(buffer), 0);
  if (n <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "recv() failed");
    return NULL;
  }

  // Allocate and copy data into ogs_pkbuf_t
  recvbuf = ogs_pkbuf_alloc(packet_pool, n);
  ogs_assert(recvbuf);
  memcpy(recvbuf->data, buffer, n);
  ogs_pkbuf_put(recvbuf, n);

  return recvbuf;
}

// Modified ogs_tun_write
int ogs_tun_write(ogs_socket_t fd, ogs_pkbuf_t *pkbuf) {
  char buffer[OGS_MAX_PKT_LEN + 64]; // Extra space for proxy headers
  int proxy_fd;                      // Retrieve proxy_fd from mapping table
  int n;

  ogs_assert(fd != INVALID_SOCKET);
  ogs_assert(pkbuf);

  // Retrieve the proxy_fd associated with this fd
  proxy_fd = fd; // Assume fd is already mapped to proxy_fd

  // Send write request to proxy
  snprintf(buffer, sizeof(buffer), "WRITE %d %d\n", fd, pkbuf->len);
  n = send(proxy_fd, buffer, strlen(buffer), 0);
  if (n <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "send() failed");
    return OGS_ERROR;
  }

  // Send the actual packet data
  n = send(proxy_fd, pkbuf->data, pkbuf->len, 0);
  if (n <= 0) {
    ogs_log_message(OGS_LOG_ERROR, errno, "send() failed");
    return OGS_ERROR;
  }

  return OGS_OK;
}
