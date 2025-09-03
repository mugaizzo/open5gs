#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "/tmp/tun_service.sock"
#define BUFFER_SIZE 1024
#define RETRY_DELAY_SECONDS 2 // Retry every 2 seconds

int main() {
  int client_fd;
  struct sockaddr_un addr;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

  // Attempt to connect to the server in a loop
  while (1) {
    client_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_fd < 0) {
      perror("socket");
      exit(EXIT_FAILURE);
    }

    if (connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      printf("Connected to the server.\n");
      break; // Exit the loop if connected
    } else {
      fprintf(
          stderr,
          "Failed to connect to the server: %s. Retrying in %d seconds...\n",
          strerror(errno), RETRY_DELAY_SECONDS);
      close(client_fd);
      sleep(RETRY_DELAY_SECONDS);
    }
  }

  // Example command to open a TUN interface
  char *command = "OPEN_TUN tun0 0"; // "interface_name is_tap"
  write(client_fd, command, strlen(command));
  printf("Sent command: %s\n", command);

  char buffer[BUFFER_SIZE];
  ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';
    printf("Received response: %s\n", buffer);
  }

  // Close the connection
  close(client_fd);
  return 0;
}
