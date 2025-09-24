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

  /* Buffer for data */
  uint8_t buffer[TUN_PROXY_BUFFER_SIZE];
  uint32_t buffer_len;
  uint32_t expected_len;
  bool reading_length;
} tun_proxy_client_t;

typedef struct tun_proxy_context_s {
  ogs_sock_t *server_sock;
  ogs_poll_t *server_poll;
  ogs_pollset_t *pollset;

  ogs_list_t client_list;

  bool running;
} tun_proxy_context_t;

static tun_proxy_context_t g_proxy_ctx;

/* Function prototypes */
static void tun_proxy_event_handler(short when, ogs_socket_t fd, void *data);
static tun_proxy_client_t *tun_proxy_client_create(ogs_socket_t client_fd);
static void tun_proxy_client_destroy(tun_proxy_client_t *client);
static int tun_proxy_setup_tun(tun_proxy_client_t *client, const char *ifname,
                               int is_tap);
static void signal_handler(int sig);

/* Open a TUN/TAP device */
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

/* Create a new client */
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
  client->reading_length = false;
  client->buffer_len = 0;

  /* Set client socket to non-blocking */
  int flags = fcntl(client_fd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
  }

  client->client_poll =
      ogs_pollset_add(g_proxy_ctx.pollset, OGS_POLLIN, client_fd,
                      tun_proxy_event_handler, client);
  if (!client->client_poll) {
    ogs_error("Failed to add client to pollset");
    ogs_free(client);
    return NULL;
  }

  ogs_list_add(&g_proxy_ctx.client_list, &client->node);
  ogs_info("New client connected (fd=%d)", client_fd);

  return client;
}

/* Destroy a client */
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

/* Setup TUN interface for client */
static int tun_proxy_setup_tun(tun_proxy_client_t *client, const char *ifname,
                               int is_tap) {
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
                      tun_proxy_event_handler, client);
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

/* Parse setup message from client */
static int tun_proxy_parse_setup_message(const char *msg, char *ifname,
                                         int *is_tap) {
  int result = OGS_ERROR;
  const char *prefix = "SETUP:";
  size_t prefix_len = strlen(prefix);

  ogs_assert(msg);
  ogs_assert(ifname);
  ogs_assert(is_tap);

  /* Check for SETUP: prefix */
  if (strncmp(msg, prefix, prefix_len) != 0) {
    ogs_error("Invalid setup message format (missing SETUP: prefix)");
    return OGS_ERROR;
  }

  /* Find the first colon after prefix */
  const char *ifname_start = msg + prefix_len;
  const char *colon = strchr(ifname_start, ':');

  if (!colon) {
    ogs_error(
        "Invalid setup message format (missing colon after interface name)");
    return OGS_ERROR;
  }

  /* Copy the interface name */
  size_t ifname_len = colon - ifname_start;
  if (ifname_len >= IFNAMSIZ) {
    ogs_error("Interface name too long");
    return OGS_ERROR;
  }

  memcpy(ifname, ifname_start, ifname_len);
  ifname[ifname_len] = '\0';

  /* Parse is_tap value */
  *is_tap = atoi(colon + 1);

  return OGS_OK;
}

/* Handle events for both server, client and TUN */
static void tun_proxy_event_handler(short when, ogs_socket_t fd, void *data) {
  tun_proxy_client_t *client = data;
  ssize_t bytes;
  uint32_t len_network, len_host;

  /* Server socket event (new connection) */
  if (!client && fd == g_proxy_ctx.server_sock->fd) {
    ogs_sock_t *new_sock = ogs_sock_accept(g_proxy_ctx.server_sock);
    if (!new_sock) {
      ogs_warn("Failed to accept client connection");
      return;
    }

    tun_proxy_client_t *new_client = tun_proxy_client_create(new_sock->fd);
    if (!new_client) {
      ogs_error("Failed to create client context");
      ogs_sock_destroy(new_sock);
      return;
    }

    /* fd now managed by client */
    ogs_free(new_sock);
    return;
  }

  ogs_assert(client);

  /* Handle client socket events */
  if (fd == client->client_fd) {
    if (when & OGS_POLLIN) {
      if (!client->setup_complete) {
        /* Reading setup message */
        bytes = ogs_recv(fd, client->buffer + client->buffer_len,
                         TUN_PROXY_BUFFER_SIZE - client->buffer_len - 1, 0);

        if (bytes <= 0) {
          if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
          }
          ogs_info("Client disconnected during setup");
          tun_proxy_client_destroy(client);
          return;
        }

        client->buffer_len += bytes;
        client->buffer[client->buffer_len] =
            '\0'; /* Null terminate for string ops */

        /* Check if we have a complete setup message (ending with newline) */
        char *newline = memchr(client->buffer, '\n', client->buffer_len);
        if (newline) {
          *newline = '\0'; /* Replace newline with null terminator */

          ogs_info("Received setup message: %s", client->buffer);

          char ifname[IFNAMSIZ];
          int is_tap;

          if (tun_proxy_parse_setup_message((char *)client->buffer, ifname,
                                            &is_tap) == OGS_OK) {
            if (tun_proxy_setup_tun(client, ifname, is_tap) != OGS_OK) {
              ogs_error("TUN setup failed");
              tun_proxy_client_destroy(client);
              return;
            }
          } else {
            ogs_error("Invalid setup message");
            tun_proxy_client_destroy(client);
            return;
          }

          client->buffer_len = 0;
          client->reading_length = true;
        } else if (client->buffer_len >= TUN_PROXY_BUFFER_SIZE - 1) {
          ogs_error("Setup message too long");
          tun_proxy_client_destroy(client);
          return;
        }
      } else if (client->reading_length) {
        /* Reading packet length */
        bytes = ogs_recv(fd, client->buffer + client->buffer_len,
                         sizeof(uint32_t) - client->buffer_len, 0);

        if (bytes <= 0) {
          if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
          }
          ogs_info("Client disconnected");
          tun_proxy_client_destroy(client);
          return;
        }

        client->buffer_len += bytes;

        if (client->buffer_len == sizeof(uint32_t)) {
          /* We have the complete length */
          memcpy(&len_network, client->buffer, sizeof(uint32_t));
          len_host = ntohl(len_network);

          if (len_host > TUN_PROXY_BUFFER_SIZE) {
            ogs_error("Packet too large: %u", len_host);
            tun_proxy_client_destroy(client);
            return;
          }

          client->expected_len = len_host;
          client->buffer_len = 0;
          client->reading_length = false;
        }
      } else {
        /* Reading packet data */
        bytes = ogs_recv(fd, client->buffer + client->buffer_len,
                         client->expected_len - client->buffer_len, 0);

        if (bytes <= 0) {
          if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return;
          }
          ogs_info("Client disconnected");
          tun_proxy_client_destroy(client);
          return;
        }

        client->buffer_len += bytes;

        if (client->buffer_len == client->expected_len) {
          /* Write complete packet to TUN */
          bytes = ogs_write(client->tun_fd, client->buffer, client->buffer_len);
          if (bytes < 0) {
            ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                            "TUN write failed");
          } else if ((uint32_t)bytes != client->buffer_len) {
            ogs_warn("Partial TUN write: %zd/%u", bytes, client->buffer_len);
          }

          /* Reset for next packet */
          client->buffer_len = 0;
          client->reading_length = true;
        }
      }
    } else if (when & (POLL_HUP | POLL_ERR)) {
      ogs_info("Client socket error or hangup");
      tun_proxy_client_destroy(client);
      return;
    }
  }
  /* Handle TUN events */
  else if (fd == client->tun_fd) {
    if (when & OGS_POLLIN) {
      /* Read packet from TUN */
      bytes = ogs_read(client->tun_fd, client->buffer, TUN_PROXY_BUFFER_SIZE);

      if (bytes <= 0) {
        if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          return;
        }
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "TUN read failed");
        return;
      }

      /* Send packet to client: first length, then data */
      len_host = (uint32_t)bytes;
      len_network = htonl(len_host);

      bytes = ogs_send(client->client_fd, &len_network, sizeof(len_network), 0);
      if (bytes != sizeof(len_network)) {
        if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          ogs_warn("Client buffer full, packet dropped");
          return;
        }
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "Failed to send length header");
        tun_proxy_client_destroy(client);
        return;
      }

      bytes = ogs_send(client->client_fd, client->buffer, len_host, 0);
      if (bytes != (ssize_t)len_host) {
        if (bytes < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
          ogs_warn("Client buffer full, packet dropped");
          return;
        }
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "Failed to send packet data");
        tun_proxy_client_destroy(client);
        return;
      }
    } else if (when & (POLL_HUP | POLL_ERR)) {
      ogs_error("TUN device error");
      tun_proxy_client_destroy(client);
      return;
    }
  }
}

/* Initialize the proxy server */
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

  g_proxy_ctx.server_poll = ogs_pollset_add(g_proxy_ctx.pollset, OGS_POLLIN,
                                            g_proxy_ctx.server_sock->fd,
                                            tun_proxy_event_handler, NULL);

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

/* Clean up server resources */
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

/* Signal handler for clean shutdown */
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
  ogs_core_terminate();

  return EXIT_SUCCESS;
}
