/*
 * Proxy-based TUN implementation for restricted environments
 */

#include "ogs-tun.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __ogs_sock_domain

#define TUN_PROXY_SERVER_HOST "127.0.0.1" // Configure as needed
#define TUN_PROXY_SERVER_PORT 9999

ogs_socket_t ogs_tun_open(char *ifname, int len, int is_tap) {
  ogs_socket_t fd = INVALID_SOCKET;
  struct sockaddr_in server_addr;
  int rc;

  ogs_assert(ifname);

  // Create TCP socket to proxy server
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "socket() failed for TUN proxy");
    return INVALID_SOCKET;
  }

  // Set socket to non-blocking
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "fcntl(F_GETFL) failed");
    close(fd);
    return INVALID_SOCKET;
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "fcntl(F_SETFL) failed");
    close(fd);
    return INVALID_SOCKET;
  }

  // Connect to proxy server
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(TUN_PROXY_SERVER_PORT);
  inet_pton(AF_INET, TUN_PROXY_SERVER_HOST, &server_addr.sin_addr);

  rc = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  if (rc < 0 && errno != EINPROGRESS) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "connect() failed to TUN proxy server");
    close(fd);
    return INVALID_SOCKET;
  }

  // Send interface setup request to server
  char setup_msg[256];
  snprintf(setup_msg, sizeof(setup_msg), "SETUP:%s:%d\n", ifname, is_tap);

  // For non-blocking connect, we might need to wait
  if (rc < 0 && errno == EINPROGRESS) {
    fd_set write_fds;
    struct timeval tv;
    FD_ZERO(&write_fds);
    FD_SET(fd, &write_fds);
    tv.tv_sec = 5; // 5 second timeout
    tv.tv_usec = 0;

    rc = select(fd + 1, NULL, &write_fds, NULL, &tv);
    if (rc <= 0) {
      ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                      "connection timeout to TUN proxy server");
      close(fd);
      return INVALID_SOCKET;
    }

    // Check if connection succeeded
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error) {
      ogs_log_message(OGS_LOG_ERROR, error ? error : ogs_socket_errno,
                      "connection failed to TUN proxy server");
      close(fd);
      return INVALID_SOCKET;
    }
  }

  // Send setup message (handle partial writes)
  ogs_info("Sending setup message: %s", setup_msg);
  size_t to_send = strlen(setup_msg);
  size_t total_sent = 0;
  
  while (total_sent < to_send) {
    ssize_t sent = send(fd, setup_msg + total_sent, to_send - total_sent, 0);
    if (sent < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Would block, try again after a short delay
        usleep(10000);  // 10ms
        continue;
      }
      ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                      "failed to send setup message");
      close(fd);
      return INVALID_SOCKET;
    }
    total_sent += sent;
  }

  ogs_info("TUN proxy connection established for interface: %s", ifname);
  return fd;
}

int ogs_tun_set_ip(char *ifname, ogs_ipsubnet_t *gw, ogs_ipsubnet_t *sub) {
  // IP configuration is handled by the proxy server
  return OGS_OK;
}
