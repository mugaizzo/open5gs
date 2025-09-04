#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define PORT 12345
#define BUFFER_SIZE 8192

typedef struct {
  int client_fd;
  int file_fd; // File descriptor for the actual file
} ClientContext;

static void handle_client(int client_socket) {
  char buffer[BUFFER_SIZE];
  int file_fd = -1;

  while (1) {
    // Receive a command from the client
    memset(buffer, 0, BUFFER_SIZE);
    ssize_t received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (received <= 0) {
      printf("Client disconnected or error receiving: %s\n", strerror(errno));
      break;
    }

    buffer[received] = '\0';

    // Parse the command
    char command[16];
    char args[BUFFER_SIZE];
    sscanf(buffer, "%s %[^\n]", command, args);

    if (strcmp(command, "OPEN") == 0) {
      // Extract filename and mode from args
      char ifname[IFNAMSIZ];
      int is_tap;
      sscanf(args, "%s %d", ifname, &is_tap);

      // Open the TUN/TAP device
      const char *dev = "/dev/net/tun";
      struct ifreq ifr;
      int flags = IFF_NO_PI;

      file_fd = open(dev, O_RDWR);
      if (file_fd < 0) {
        perror("open() failed");
        send(client_socket, "-1\n", 3, 0);
        continue;
      }

      // Clear and configure the ifreq structure
      memset(&ifr, 0, sizeof(ifr));
      ifr.ifr_flags = (is_tap ? (flags | IFF_TAP) : (flags | IFF_TUN));
      strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

      // Set up the TUN/TAP interface
      if (ioctl(file_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF) failed");
        close(file_fd);
        file_fd = -1;
        send(client_socket, "-1\n", 3, 0);
        continue;
      }

      printf("Opened TUN/TAP device '%s' with fd %d\n", ifname, file_fd);

      // Send back the file descriptor as a response
      char response[32];
      snprintf(response, sizeof(response), "%d\n", file_fd);
      send(client_socket, response, strlen(response), 0);

    } else if (strcmp(command, "READ") == 0) {
      // Read data from the TUN/TAP device
      int fd;
      sscanf(args, "%d", &fd);

      if (fd != file_fd) {
        send(client_socket, "Invalid fd\n", 11, 0);
        continue;
      }

      ssize_t bytes_read = read(file_fd, buffer, BUFFER_SIZE);
      if (bytes_read < 0) {
        perror("read() failed");
        send(client_socket, "READ_ERROR\n", 11, 0);
      } else {
        send(client_socket, buffer, bytes_read, 0);
      }
    } else if (strcmp(command, "WRITE") == 0) {
      // Parse arguments for fd and length
      int fd, length;
      sscanf(args, "%d %d", &fd, &length);

      if (fd != file_fd) {
        send(client_socket, "Invalid fd\n", 11, 0);
        continue;
      }

      // Receive the data to write
      memset(buffer, 0, BUFFER_SIZE);
      ssize_t data_received = recv(client_socket, buffer, length, 0);
      if (data_received <= 0) {
        perror("recv() failed");
        // send(client_socket, "WRITE_ERROR\n", 12, 0);
        continue;
      }

      // Write data to the TUN/TAP device
      ssize_t bytes_written = write(file_fd, buffer, data_received);
      if (bytes_written < 0) {
        perror("write() failed");
        send(client_socket, "WRITE_ERROR\n", 12, 0);
      } else {
        // send(client_socket, "WRITE_OK\n", 9, 0);
      }
    } else if (strcmp(command, "CLOSE") == 0) {
      // Close the TUN/TAP device
      if (close(file_fd) < 0) {
        perror("close() failed");
        send(client_socket, "CLOSE_ERROR\n", 12, 0);
      } else {
        send(client_socket, "CLOSE_OK\n", 9, 0);
        file_fd = -1;
      }
    } else {
      send(client_socket, "UNKNOWN_COMMAND\n", 17, 0);
    }
  }

  // Cleanup
  if (file_fd >= 0) {
    close(file_fd);
  }
  close(client_socket);
}

int main(void) {
  int server_socket, client_socket;
  struct sockaddr_in server_addr, client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  // Create server socket
  server_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (server_socket < 0) {
    perror("socket() failed");
    exit(EXIT_FAILURE);
  }

  // Bind the socket
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  server_addr.sin_port = htons(PORT);

  if (bind(server_socket, (struct sockaddr *)&server_addr,
           sizeof(server_addr)) < 0) {
    perror("bind() failed");
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  // Listen for incoming connections
  if (listen(server_socket, 5) < 0) {
    perror("listen() failed");
    close(server_socket);
    exit(EXIT_FAILURE);
  }

  printf("Proxy server listening on port %d...\n", PORT);

  // Accept and handle clients
  while (1) {
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr,
                           &client_addr_len);
    if (client_socket < 0) {
      perror("accept() failed");
      continue;
    }

    printf("Client connected\n");
    handle_client(client_socket);
  }

  close(server_socket);
  return 0;
}
