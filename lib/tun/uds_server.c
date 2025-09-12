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

#include <netdb.h>  /* For AI_PASSIVE */
#include <signal.h> /* For signal handlers */

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sock_domain

#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TUN_PROXY_DEFAULT_PORT 9999
#define TUN_PROXY_MAX_CLIENTS 256
#define TUN_PROXY_BUFFER_SIZE 2048

typedef struct tun_proxy_client_s {
  ogs_lnode_t node;

  ogs_socket_t client_fd;
  ogs_poll_t *client_poll;

  char ifname[IFNAMSIZ];
  ogs_socket_t tun_fd;
  ogs_poll_t *tun_poll;

  bool is_tap;
  bool setup_complete;

  /* Buffer for partial reads */
  uint8_t read_buffer[TUN_PROXY_BUFFER_SIZE];
  uint32_t read_offset;
  uint32_t expected_len;
  bool reading_header;
} tun_proxy_client_t;

typedef struct tun_proxy_context_s {
  ogs_sock_t *server_sock;
  ogs_poll_t *server_poll;
  ogs_pollset_t *pollset;

  ogs_list_t client_list;

  bool running;
} tun_proxy_context_t;

static tun_proxy_context_t g_proxy_ctx;

static tun_proxy_client_t *tun_proxy_client_create(ogs_socket_t client_fd);
static void tun_proxy_client_handler(short when, ogs_socket_t fd, void *data);
static void tun_proxy_client_destroy(tun_proxy_client_t *client);
static int tun_proxy_client_setup_tun(tun_proxy_client_t *client,
                                      const char *ifname, int is_tap);
static void tun_proxy_server_accept_handler(short when, ogs_socket_t fd,
                                            void *data);
static void tun_proxy_tun_handler(short when, ogs_socket_t fd, void *data);
static int tun_proxy_parse_setup_message(const char *msg, char *ifname,
                                         int *is_tap);

static ogs_socket_t tun_proxy_open_tun(const char *ifname, int is_tap) {
  ogs_socket_t fd = INVALID_SOCKET;
  const char *dev = "/dev/net/tun";
  int rc;
  struct ifreq ifr;
  int flags = IFF_NO_PI;

  ogs_assert(ifname);

  fd = open(dev, O_RDWR);
  if (fd < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "open() failed : dev[%s]",
                    dev);
    return INVALID_SOCKET;
  }

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = (is_tap ? (flags | IFF_TAP) : (flags | IFF_TUN));
  strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

  rc = ioctl(fd, TUNSETIFF, (void *)&ifr);
  if (rc < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "ioctl() failed : dev[%s] flags[0x%x]", dev, flags);
    close(fd);
    return INVALID_SOCKET;
  }

  /* Set non-blocking */
  int sock_flags = fcntl(fd, F_GETFL, 0);
  if (sock_flags < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "fcntl(F_GETFL) failed");
    close(fd);
    return INVALID_SOCKET;
  }

  if (fcntl(fd, F_SETFL, sock_flags | O_NONBLOCK) < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "fcntl(F_SETFL) failed");
    close(fd);
    return INVALID_SOCKET;
  }

  ogs_info("TUN device opened: %s (fd=%d, tap=%d)", ifname, fd, is_tap);
  return fd;
}

static tun_proxy_client_t *tun_proxy_client_create(ogs_socket_t client_fd) {
  tun_proxy_client_t *client = NULL;

  client = ogs_calloc(1, sizeof(*client));
  if (!client) {
    ogs_error("ogs_calloc() failed");
    return NULL;
  }

  client->client_fd = client_fd;
  client->tun_fd = INVALID_SOCKET;
  client->setup_complete = false;
  client->reading_header = true;
  client->expected_len = sizeof(uint32_t);
  client->read_offset = 0;

  /* Set client socket to non-blocking */
  int flags = fcntl(client_fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
  }

  client->client_poll =
      ogs_pollset_add(g_proxy_ctx.pollset, OGS_POLLIN, client_fd,
                      tun_proxy_client_handler, client);
  if (!client->client_poll) {
    ogs_error("Failed to add client to pollset");
    ogs_free(client);
    return NULL;
  }

  ogs_list_add(&g_proxy_ctx.client_list, &client->node);
  ogs_info("New client connected (fd=%d)", client_fd);

  return client;
}

static void tun_proxy_client_destroy(tun_proxy_client_t *client) {
  ogs_assert(client);

  ogs_info("Destroying client (fd=%d, tun_fd=%d)", client->client_fd,
           client->tun_fd);

  if (client->client_poll) {
    ogs_pollset_remove(client->client_poll);
    client->client_poll = NULL;
  }

  if (client->tun_poll) {
    ogs_pollset_remove(client->tun_poll);
    client->tun_poll = NULL;
  }

  if (client->client_fd != INVALID_SOCKET) {
    ogs_closesocket(client->client_fd);
    client->client_fd = INVALID_SOCKET;
  }

  if (client->tun_fd != INVALID_SOCKET) {
    close(client->tun_fd);
    client->tun_fd = INVALID_SOCKET;
  }

  ogs_list_remove(&g_proxy_ctx.client_list, &client->node);
  ogs_free(client);
}

static int tun_proxy_client_setup_tun(tun_proxy_client_t *client,
                                      const char *ifname, int is_tap) {
  ogs_assert(client);
  ogs_assert(ifname);

  if (client->tun_fd != INVALID_SOCKET) {
    ogs_warn("TUN already setup for client");
    return OGS_ERROR;
  }

  strncpy(client->ifname, ifname, sizeof(client->ifname) - 1);
  client->is_tap = is_tap;

  client->tun_fd = tun_proxy_open_tun(ifname, is_tap);
  if (client->tun_fd == INVALID_SOCKET) {
    ogs_error("Failed to open TUN device: %s", ifname);
    return OGS_ERROR;
  }

  client->tun_poll =
      ogs_pollset_add(g_proxy_ctx.pollset, OGS_POLLIN, client->tun_fd,
                      tun_proxy_tun_handler, client);
  if (!client->tun_poll) {
    ogs_error("Failed to add TUN to pollset");
    close(client->tun_fd);
    client->tun_fd = INVALID_SOCKET;
    return OGS_ERROR;
  }

  client->setup_complete = true;
  ogs_info("TUN setup complete for client: %s", ifname);

  return OGS_OK;
}

static int tun_proxy_parse_setup_message(const char *msg, char *ifname,
                                         int *is_tap) {
  char *token;
  char *msg_copy;
  int result = OGS_ERROR;

  ogs_assert(msg);
  ogs_assert(ifname);
  ogs_assert(is_tap);

  msg_copy = ogs_strdup(msg);
  if (!msg_copy) {
    ogs_error("ogs_strdup() failed");
    return OGS_ERROR;
  }

  /* Parse "SETUP:ifname:is_tap\n" */
  token = strtok(msg_copy, ":");
  if (token && strcmp(token, "SETUP") == 0) {
    token = strtok(NULL, ":");
    if (token) {
      strncpy(ifname, token, IFNAMSIZ - 1);
      ifname[IFNAMSIZ - 1] = '\0';

      token = strtok(NULL, ":\n");
      if (token) {
        *is_tap = atoi(token);
        result = OGS_OK;
      }
    }
  }

  ogs_free(msg_copy);
  return result;
}

static void tun_proxy_server_accept_handler(short when, ogs_socket_t fd,
                                            void *data) {
  ogs_sock_t *new_sock = NULL;
  tun_proxy_client_t *client = NULL;

  ogs_assert(when == OGS_POLLIN);
  ogs_assert(fd == g_proxy_ctx.server_sock->fd);

  new_sock = ogs_sock_accept(g_proxy_ctx.server_sock);
  if (!new_sock) {
    ogs_warn("Failed to accept client connection");
    return;
  }

  client = tun_proxy_client_create(new_sock->fd);
  if (!client) {
    ogs_error("Failed to create client context");
    ogs_sock_destroy(new_sock);
    return;
  }

  /* Don't destroy new_sock - fd is now managed by client */
  ogs_free(new_sock);
}

static void tun_proxy_client_handler(short when, ogs_socket_t fd, void *data) {
  tun_proxy_client_t *client = data;
  ssize_t received;
  uint32_t packet_len;
  bool client_disconnected = false;

  ogs_assert(client);
  ogs_assert(fd == client->client_fd);

  if (when & OGS_POLLIN) {
    while (true) {
      if (client->reading_header) {
        /* Read length header */
        received = ogs_recv(
            client->client_fd, client->read_buffer + client->read_offset,
            /* change client->expected_len  */ client->expected_len -
                client->read_offset,
            0);

        ogs_info("Received raw setup message: %s", (char *)client->read_buffer);
        if (received <= 0) {
          if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return; /* No more data */
          }
          ogs_info("Client disconnected (fd=%d)", client->client_fd);
          client_disconnected = true;
          break;
        }

        client->read_offset += received;

        if (client->read_offset >= client->expected_len) {
          if (!client->setup_complete) {
            /* This is setup message */
            client->read_buffer[client->read_offset] = '\0';

            char ifname[IFNAMSIZ];
            int is_tap;

            if (tun_proxy_parse_setup_message((char *)client->read_buffer,
                                              ifname, &is_tap) == OGS_OK) {
              if (tun_proxy_client_setup_tun(client, ifname, is_tap) ==
                  OGS_OK) {
                ogs_info("Client setup complete: %s", ifname);
              } else {
                ogs_error("TUN setup failed for client");
                client_disconnected = true;
                break;
              }
            } else {
              ogs_error("Invalid setup message from client");
              client_disconnected = true;
              break;
            }

            /* Reset for packet reading */
            client->reading_header = true;
            client->expected_len = sizeof(uint32_t);
            client->read_offset = 0;
          } else {
            /* Got length header */
            memcpy(&packet_len, client->read_buffer, sizeof(packet_len));
            packet_len = ntohl(packet_len);

            if (packet_len > TUN_PROXY_BUFFER_SIZE - sizeof(uint32_t)) {
              ogs_error("Packet too large: %u", packet_len);
              client_disconnected = true;
              break;
            }

            client->reading_header = false;
            client->expected_len = packet_len;
            client->read_offset = 0;
          }
        }
      } else {
        /* Read packet data */
        received = ogs_recv(client->client_fd,
                            client->read_buffer + client->read_offset,
                            client->expected_len - client->read_offset, 0);

        if (received <= 0) {
          if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return; /* No more data */
          }
          ogs_info("Client disconnected (fd=%d)", client->client_fd);
          client_disconnected = true;
          break;
        }

        client->read_offset += received;

        if (client->read_offset >= client->expected_len) {
          /* Complete packet received, write to TUN */
          if (client->tun_fd != INVALID_SOCKET) {
            ssize_t written = ogs_write(client->tun_fd, client->read_buffer,
                                        client->expected_len);
            if (written < 0) {
              ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                              "TUN write failed");
            } else if (written != client->expected_len) {
              ogs_warn("Partial TUN write: %zd/%u", written,
                       client->expected_len);
            }
          }

          /* Reset for next packet */
          client->reading_header = true;
          client->expected_len = sizeof(uint32_t);
          client->read_offset = 0;
        }
      }
    }
  }

  if (client_disconnected) {
    tun_proxy_client_destroy(client);
  }
}

static void tun_proxy_tun_handler(short when, ogs_socket_t fd, void *data) {
  tun_proxy_client_t *client = data;
  uint8_t buffer[TUN_PROXY_BUFFER_SIZE];
  ssize_t bytes_read;
  uint32_t packet_len_net;

  ogs_assert(client);
  ogs_assert(fd == client->tun_fd);

  if (when & OGS_POLLIN) {
    bytes_read = ogs_read(client->tun_fd, buffer, sizeof(buffer));
    if (bytes_read <= 0) {
      if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return; /* No data available */
      }
      ogs_log_message(OGS_LOG_WARN, ogs_socket_errno, "TUN read failed");
      return;
    }

    if (client->client_fd != INVALID_SOCKET && client->setup_complete) {
      /* Send length header first */
      packet_len_net = htonl((uint32_t)bytes_read);
      ssize_t sent = ogs_send(client->client_fd, &packet_len_net,
                              sizeof(packet_len_net), 0);
      if (sent != sizeof(packet_len_net)) {
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          /* Client buffer full - should implement buffering */
          ogs_warn("Client send buffer full");
          return;
        }
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                        "Failed to send length header");
        return;
      }

      /* Send packet data */
      sent = ogs_send(client->client_fd, buffer, bytes_read, 0);
      if (sent != bytes_read) {
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          /* Client buffer full - should implement buffering */
          ogs_warn("Client send buffer full");
          return;
        }
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                        "Failed to send packet data");
      }
    }
  }
}

static int tun_proxy_server_init(int port) {
  int rv;
  ogs_sockaddr_t *addr = NULL;

  memset(&g_proxy_ctx, 0, sizeof(g_proxy_ctx));
  ogs_list_init(&g_proxy_ctx.client_list);

  g_proxy_ctx.pollset = ogs_pollset_create((TUN_PROXY_MAX_CLIENTS * 2) + 1);
  if (!g_proxy_ctx.pollset) {
    ogs_error("Failed to create pollset");
    return OGS_ERROR;
  }

  rv = ogs_getaddrinfo(&addr, AF_INET, NULL, (uint16_t)port, AI_PASSIVE);
  if (rv != OGS_OK) {
    ogs_error("ogs_getaddrinfo() failed");
    return OGS_ERROR;
  }

  g_proxy_ctx.server_sock = ogs_tcp_server(addr, NULL);
  if (!g_proxy_ctx.server_sock) {
    ogs_error("Failed to create TCP server");
    ogs_freeaddrinfo(addr);
    return OGS_ERROR;
  }

  g_proxy_ctx.server_poll = ogs_pollset_add(
      g_proxy_ctx.pollset, OGS_POLLIN, g_proxy_ctx.server_sock->fd,
      tun_proxy_server_accept_handler, NULL);

  if (!g_proxy_ctx.server_poll) {
    ogs_error("Failed to add server to pollset");
    ogs_sock_destroy(g_proxy_ctx.server_sock);
    ogs_freeaddrinfo(addr);
    return OGS_ERROR;
  }

  ogs_info("TUN proxy server listening on port %d", port);
  ogs_freeaddrinfo(addr);

  g_proxy_ctx.running = true;
  return OGS_OK;
}

static void tun_proxy_server_cleanup(void) {
  tun_proxy_client_t *client = NULL, *next_client = NULL;

  g_proxy_ctx.running = false;

  /* Cleanup all clients */
  ogs_list_for_each_safe(&g_proxy_ctx.client_list, next_client, client) {
    tun_proxy_client_destroy(client);
  }

  if (g_proxy_ctx.server_poll) {
    ogs_pollset_remove(g_proxy_ctx.server_poll);
    g_proxy_ctx.server_poll = NULL;
  }

  if (g_proxy_ctx.server_sock) {
    ogs_sock_destroy(g_proxy_ctx.server_sock);
    g_proxy_ctx.server_sock = NULL;
  }

  if (g_proxy_ctx.pollset) {
    ogs_pollset_destroy(g_proxy_ctx.pollset);
    g_proxy_ctx.pollset = NULL;
  }

  ogs_info("TUN proxy server shutdown complete");
}

static void signal_handler(int sig) {
  ogs_info("Received signal %d, shutting down...", sig);
  g_proxy_ctx.running = false;
}

int main(int argc, char **argv) {
  int rv;
  int port = TUN_PROXY_DEFAULT_PORT;

  /* Initialize Open5GS core */
  ogs_core_initialize();

  if (argc > 1) {
    port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
      ogs_error("Invalid port number: %s", argv[1]);
      return EXIT_FAILURE;
    }
  }

  /* Setup signal handlers */
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  rv = tun_proxy_server_init(port);
  if (rv != OGS_OK) {
    ogs_error("Failed to initialize TUN proxy server");
    return EXIT_FAILURE;
  }

  /* Main event loop */
  while (g_proxy_ctx.running) {
    rv = ogs_pollset_poll(g_proxy_ctx.pollset, ogs_time_from_msec(1000));
    if (rv == OGS_ERROR) {
      ogs_error("Poll error, shutting down");
      break;
    }
    /* OGS_TIMEUP is normal for timeout */
  }

  tun_proxy_server_cleanup();

  return EXIT_SUCCESS;
}
