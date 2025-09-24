#include "ogs-core.h"
#include "ogs-tun.h"

// Protocol: [4-byte length][data]
ogs_pkbuf_t *ogs_tun_read(ogs_socket_t fd, ogs_pkbuf_pool_t *packet_pool) {
  ogs_pkbuf_t *recvbuf = NULL;
  uint32_t packet_len;
  int n;

  ogs_assert(fd != INVALID_SOCKET);

  // First, read the length header
  n = ogs_recv(fd, &packet_len, sizeof(packet_len), 0);
  if (n <= 0) {
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return NULL; // No data available (non-blocking)
    }
    ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                    "ogs_read() failed for length");
    return NULL;
  }

  if (n < sizeof(packet_len)) {
    ogs_log_message(OGS_LOG_WARN, 0, "partial length read");
    return NULL;
  }

  packet_len = ntohl(packet_len);
  if (packet_len > OGS_MAX_PKT_LEN) {
    ogs_error("packet too large: %d", packet_len);
    return NULL;
  }

  recvbuf = ogs_pkbuf_alloc(packet_pool, packet_len + OGS_TUN_MAX_HEADROOM);
  ogs_assert(recvbuf);
  ogs_pkbuf_reserve(recvbuf, OGS_TUN_MAX_HEADROOM);
  ogs_pkbuf_put(recvbuf, packet_len);

  // Read the actual packet data
  n = ogs_recv(fd, recvbuf->data, packet_len, 0);
  if (n != packet_len) {
    ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                    "incomplete packet read: expected %d, got %d", packet_len,
                    n);
    ogs_pkbuf_free(recvbuf);
    return NULL;
  }

  return recvbuf;
}

int ogs_tun_write(ogs_socket_t fd, ogs_pkbuf_t *pkbuf) {
  uint32_t packet_len;

  ogs_assert(fd != INVALID_SOCKET);
  ogs_assert(pkbuf);

  packet_len = htonl(pkbuf->len);

  // Send length header first
  if (ogs_send(fd, &packet_len, sizeof(packet_len), 0) != sizeof(packet_len)) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "failed to write length header");
    return OGS_ERROR;
  }

  // Send packet data
  if (ogs_send(fd, pkbuf->data, pkbuf->len, 0) != pkbuf->len) {
    ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                    "failed to write packet data");
    return OGS_ERROR;
  }

  return OGS_OK;
}
