#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "linux-setup.h" // if available; otherwise forward-declare below
#include "ogs-tun.h"     // for ogs_tun_* prototypes and types

// Forward declarations in case headers don't expose them
int connect_to_server(void);
int send_packet(int sockfd, const void *buf, size_t len);
int recv_packet(int sockfd, void *buf, size_t len);

// uds_server.c functions
int open_tun_interface(char *ifname, int is_tap);
int close_tun_interface(int tun_fd);
void handle_client(int client_fd, int *tun_fd);

#define TEST_PORT 55555
#define BUFFER_SIZE 4096

// Simple assert macro for tests
#define TASSERT(cond, fmt, ...)                                                \
  do {                                                                         \
    if (!(cond)) {                                                             \
      fprintf(stderr, "ASSERT FAILED: %s:%d: " fmt "\n", __FILE__, __LINE__,   \
              ##__VA_ARGS__);                                                  \
      return -1;                                                               \
    }                                                                          \
  } while (0)

static void msleep(int ms) {
  struct timespec ts;
  ts.tv_sec = ms / 1000;
  ts.tv_nsec = (ms % 1000) * 1000000L;
  nanosleep(&ts, NULL);
}

/* ------------------------- Fake proxy TCP server ------------------------- */

static ssize_t read_line(int fd, char *buf, size_t max) {
  size_t off = 0;
  while (off + 1 < max) {
    char c;
    ssize_t r = read(fd, &c, 1);
    if (r == 0)
      break;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    buf[off++] = c;
    if (c == '\n')
      break;
  }
  buf[off] = '\0';
  return (ssize_t)off;
}

static void *fake_proxy_server(void *arg) {
  (void)arg;
  int srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv < 0) {
    perror("[TEST] socket");
    return NULL;
  }
  int opt = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(TEST_PORT);

  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("[TEST] bind");
    close(srv);
    return NULL;
  }
  if (listen(srv, 1) < 0) {
    perror("[TEST] listen");
    close(srv);
    return NULL;
  }

  int cli = accept(srv, NULL, NULL);
  if (cli < 0) {
    perror("[TEST] accept");
    close(srv);
    return NULL;
  }

  char line[256];
  for (;;) {
    ssize_t n = read_line(cli, line, sizeof(line));
    if (n <= 0)
      break;

    if (strncmp(line, "OPEN_TUN", 8) == 0) {
      const char ok[] = "OK\n";
      write(cli, ok, sizeof(ok) - 1);
    } else if (strncmp(line, "READ_TUN", 8) == 0) {
      // send a dummy payload
      const char payload[] = "TEST_PAYLOAD_FROM_SERVER";
      write(cli, payload, sizeof(payload) - 1);
    } else if (strncmp(line, "WRITE_TUN", 9) == 0) {
      size_t data_len = 0;
      const char *args = line + 9;
      if (*args == ' ')
        args++;
      if (sscanf(args, "%zu", &data_len) != 1) {
        const char err[] = "ERROR\n";
        write(cli, err, sizeof(err) - 1);
        continue;
      }
      // Read exactly data_len bytes
      size_t remain = data_len;
      char buf[BUFFER_SIZE];
      while (remain > 0) {
        size_t chunk = remain > sizeof(buf) ? sizeof(buf) : remain;
        ssize_t r = read(cli, buf, chunk);
        if (r <= 0)
          break;
        remain -= (size_t)r;
      }
      const char ok[] = "OK\n";
      write(cli, ok, sizeof(ok) - 1);
    } else {
      const char err[] = "ERROR\n";
      write(cli, err, sizeof(err) - 1);
    }
  }

  close(cli);
  close(srv);
  return NULL;
}

/* ----------------------------- Test helpers ----------------------------- */

static int test_linux_setup_and_tunio_basic(void) {
  // Start fake proxy server
  pthread_t th;
  TASSERT(pthread_create(&th, NULL, fake_proxy_server, NULL) == 0,
          "pthread_create failed");

  // Give the server a moment
  msleep(100);

  // ogs_tun_open -> connect_to_server + OPEN_TUN/OK
  char ifname[IFNAMSIZ] = "ogstun";
  int fd = ogs_tun_open(ifname, (int)strlen(ifname), 0);
  TASSERT(fd >= 0, "ogs_tun_open failed");

  // Directly exercise small-buffer recv_packet path with WRITE_TUN 0
  {
    char cmd[] = "WRITE_TUN 0\n";
    int s = send_packet(fd, cmd, sizeof(cmd) - 1);
    TASSERT(s == (int)(sizeof(cmd) - 1), "send_packet failed for WRITE_TUN 0");

    char ack[16];
    int r = recv_packet(fd, ack, sizeof(ack));
    TASSERT(r > 0, "recv_packet failed to receive ACK");
    ack[r] = '\0';
    TASSERT(strcmp(ack, "OK\n") == 0, "ACK mismatch: got '%s'", ack);
  }

  // Exercise large recv_packet path with READ_TUN
  {
    char cmd[64];
    int n = snprintf(cmd, sizeof(cmd), "READ_TUN %d\n", BUFFER_SIZE);
    TASSERT(n > 0, "snprintf failed for READ_TUN");
    TASSERT(send_packet(fd, cmd, (size_t)n) == n,
            "send_packet READ_TUN failed");

    char payload[BUFFER_SIZE];
    int r = recv_packet(fd, payload, sizeof(payload));
    TASSERT(r > 0, "recv_packet for READ_TUN payload failed");
  }

  // ogs_tun_set_ip is a placeholder
  TASSERT(ogs_tun_set_ip(NULL, NULL, NULL) == OGS_OK,
          "ogs_tun_set_ip expected OGS_OK");

  // Exercise error-early paths in tunio.c
  {
    // ogs_tun_write should return error for invalid fd
    int wr = ogs_tun_write(-1, NULL);
    TASSERT(wr < 0, "ogs_tun_write(-1, NULL) should fail");

    // ogs_tun_read should return NULL for invalid fd
    ogs_pkbuf_t *rb = ogs_tun_read(-1, NULL);
    TASSERT(rb == NULL, "ogs_tun_read(-1, NULL) should return NULL");
  }

  close(fd);
  pthread_join(th, NULL);
  return 0;
}

static int read_line_fd(int fd, char *buf, size_t sz) {
  size_t off = 0;
  while (off + 1 < sz) {
    char c;
    ssize_t r = read(fd, &c, 1);
    if (r == 0)
      break;
    if (r < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    buf[off++] = c;
    if (c == '\n')
      break;
  }
  buf[off] = '\0';
  return (int)off;
}

struct handler_args {
  int fd;
  int *tun_fd_ptr;
};

static void *handler_thread(void *arg) {
  struct handler_args *ha = (struct handler_args *)arg;
  handle_client(ha->fd, ha->tun_fd_ptr);
  return NULL;
}

static int test_uds_server_handle_client_and_ifops(void) {
  // First, test open/close_tun_interface tolerance (may require privileges)
  {
    char name[IFNAMSIZ] = "ogstun_test";
    int tfd = open_tun_interface(name, 0);
    if (tfd >= 0) {
      // Able to open; then close
      TASSERT(close_tun_interface(tfd) == 0, "close_tun_interface failed");
    } else {
      // Not opened (likely due to permissions) - acceptable for unit test
    }
  }

  // Test handle_client with a socketpair (no real TUN required)
  int sp[2];
  TASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0, "socketpair failed");

  int tun_fd = -1;
  struct handler_args ha = {.fd = sp[1], .tun_fd_ptr = &tun_fd};
  pthread_t th;
  TASSERT(pthread_create(&th, NULL, handler_thread, &ha) == 0,
          "pthread_create failed");

  // 1) WRITE_TUN with no TUN open -> expect ERROR
  {
    const char *cmd = "WRITE_TUN 5\nhello";
    TASSERT(write(sp[0], cmd, strlen(cmd)) == (ssize_t)strlen(cmd),
            "write WRITE_TUN failed");
    char line[64];
    int n = read_line_fd(sp[0], line, sizeof(line));
    TASSERT(n > 0 && strcmp(line, "ERROR\n") == 0,
            "Expected ERROR for WRITE_TUN without TUN, got '%s'", line);
  }

  // 2) READ_TUN with no TUN open -> expect ERROR
  {
    const char *cmd = "READ_TUN 16\n";
    TASSERT(write(sp[0], cmd, strlen(cmd)) == (ssize_t)strlen(cmd),
            "write READ_TUN failed");
    char line[64];
    int n = read_line_fd(sp[0], line, sizeof(line));
    TASSERT(n > 0 && strcmp(line, "ERROR\n") == 0,
            "Expected ERROR for READ_TUN without TUN, got '%s'", line);
  }

  // 3) Unknown command -> ERROR
  {
    const char *cmd = "FOO\n";
    TASSERT(write(sp[0], cmd, strlen(cmd)) == (ssize_t)strlen(cmd),
            "write FOO failed");
    char line[64];
    int n = read_line_fd(sp[0], line, sizeof(line));
    TASSERT(n > 0 && strcmp(line, "ERROR\n") == 0,
            "Expected ERROR for unknown command, got '%s'", line);
  }

  // 4) CLOSE_TUN with no TUN -> ERROR
  {
    const char *cmd = "CLOSE_TUN\n";
    TASSERT(write(sp[0], cmd, strlen(cmd)) == (ssize_t)strlen(cmd),
            "write CLOSE_TUN failed");
    char line[64];
    int n = read_line_fd(sp[0], line, sizeof(line));
    TASSERT(n > 0 && strcmp(line, "ERROR\n") == 0,
            "Expected ERROR for CLOSE_TUN without TUN, got '%s'", line);
  }

  // 5) OPEN_TUN path (may fail due to permissions) -> accept OK or ERROR
  {
    const char *cmd = "OPEN_TUN ogstun 0\n";
    TASSERT(write(sp[0], cmd, strlen(cmd)) == (ssize_t)strlen(cmd),
            "write OPEN_TUN failed");
    char line[64];
    int n = read_line_fd(sp[0], line, sizeof(line));
    TASSERT(n > 0 &&
                (strcmp(line, "OK\n") == 0 || strcmp(line, "ERROR\n") == 0),
            "Expected OK or ERROR for OPEN_TUN, got '%s'", line);
  }

  // Close client side to let handler exit
  close(sp[0]);
  pthread_join(th, NULL);
  close(sp[1]);
  return 0;
}

int main(void) {
  int rc = 0;

  fprintf(stdout, "[TEST] Running linux-setup + tunio basic tests...\n");
  rc = test_linux_setup_and_tunio_basic();
  if (rc != 0) {
    fprintf(stderr, "[TEST] linux-setup/tunio tests FAILED\n");
    return 1;
  }
  fprintf(stdout, "[TEST] linux-setup + tunio basic tests PASSED\n");

  fprintf(stdout, "[TEST] Running uds_server handle_client/ifops tests...\n");
  rc = test_uds_server_handle_client_and_ifops();
  if (rc != 0) {
    fprintf(stderr, "[TEST] uds_server tests FAILED\n");
    return 1;
  }
  fprintf(stdout, "[TEST] uds_server handle_client/ifops tests PASSED\n");

  fprintf(stdout, "[TEST] All tests PASSED\n");
  return 0;
}
