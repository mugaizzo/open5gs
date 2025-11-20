#include "ogs-core.h"
#include "ogs-tun.h"
#include <unistd.h>

#define OGS_PKBUF_MAX_SIZE 2048
#define OGS_TUN_RETRY_INTERVAL_USEC 100
#define OGS_TUN_RETRY_MAX 100

/* Helper function to ensure all bytes are received on a non-blocking socket */
static int ogs_recv_all(ogs_socket_t fd, void *buf, size_t len) {
  size_t total_received = 0;
  int retry_count = 0;

  while (total_received < len) {
    ssize_t received =
        ogs_recv(fd, (char *)buf + total_received, len - total_received, 0);

    if (received > 0) {
      total_received += received;
      retry_count = 0; /* Reset retry count on successful read */
    } else if (received == 0) {
      /* Peer closed connection */
      return OGS_ERROR;
    } else { /* received < 0 */
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (++retry_count > OGS_TUN_RETRY_MAX) {
          ogs_error("recv timed out after %d retries", OGS_TUN_RETRY_MAX);
          return OGS_ERROR;
        }
        usleep(OGS_TUN_RETRY_INTERVAL_USEC); /* Wait and retry */
      } else {
        /* A real error occurred */
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno, "ogs_recv() failed");
        return OGS_ERROR;
      }
    }
  }
  return OGS_OK;
}

// Protocol: [4-byte length][data]
ogs_pkbuf_t *ogs_tun_read(ogs_socket_t fd, ogs_pkbuf_pool_t *pool) {
  uint32_t len;
  ogs_pkbuf_t *pkbuf = NULL;

  ogs_assert(pool);

  /* First, read the 4-byte length header */
  if (ogs_recv_all(fd, &len, sizeof(len)) != OGS_OK) {
    ogs_log_message(OGS_LOG_WARN, errno, "Failed to read length header");
    return NULL;
  }

  len = ntohl(len);

  if (len > OGS_PKBUF_MAX_SIZE) {
    ogs_error("packet too large: %u", len);
    /* We can't recover from this, as the stream is now misaligned. */
    /* Best effort is to return error and let caller handle it. */
    return NULL;
  }

  pkbuf = ogs_pkbuf_alloc(pool, len + OGS_TUN_MAX_HEADROOM);
  ogs_assert(pkbuf);
  ogs_pkbuf_reserve(pkbuf, OGS_TUN_MAX_HEADROOM);
  ogs_pkbuf_put(pkbuf, len);

  /* Then, read the packet data */
  if (ogs_recv_all(fd, pkbuf->data, pkbuf->len) != OGS_OK) {
    ogs_log_message(OGS_LOG_WARN, errno,
                    "incomplete packet read: expected %d", pkbuf->len);
    ogs_pkbuf_free(pkbuf);
    return NULL;
  }

  return pkbuf;
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
