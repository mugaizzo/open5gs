#include "ogs-tun.h" // Include the header file for ogs_tun_* functions
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_IFNAME "ogstun"
#define PACKET_SIZE 2048

// Global file descriptor for ogs_tun_open
static ogs_socket_t global_fd = INVALID_SOCKET;
static ogs_pkbuf_pool_t *packet_pool = NULL;

// Initialize the test environment by opening the TUN interface
static void test_initialize(void) {
  printf("Initializing test environment...\n");

  global_fd = ogs_tun_open((char *)TEST_IFNAME, strlen(TEST_IFNAME), 0);
  assert(global_fd != INVALID_SOCKET);
  printf("ogs_tun_open passed. File descriptor: %d\n", global_fd);
}

// Finalize the test environment by closing the TUN interface
static void test_finalize(void) {
  printf("Finalizing test environment...\n");

  if (global_fd != INVALID_SOCKET) {
    close(global_fd);
    printf("ogs_tun_close passed. File descriptor closed.\n");
  }
}

// Test ogs_tun_read
static void test_ogs_tun_read(void) {
  printf("Testing ogs_tun_read...\n");

  // Read data from the TUN interface
  printf("Waiting for data from TUN interface...\n");
  ogs_pkbuf_t *recvbuf = ogs_tun_read(global_fd, packet_pool);
  if (!recvbuf) {
    fprintf(stderr,
            "ogs_tun_read failed: No data received or error occurred\n");
    return;
  }
  // Print the received packet data
  printf("[RECEIVED] Packet length: %d\n", recvbuf->len);
  printf("Packet data:\n");
  int i;
  for (i = 0; i < recvbuf->len; i++) {
    printf("%02x ", recvbuf->data[i]);
  }
  printf("\n");

  // Free the packet buffer
  ogs_pkbuf_free(recvbuf);
}

// Test ogs_tun_write
static void test_ogs_tun_write(void) {
  printf("Testing ogs_tun_write...\n");

  // Allocate a packet buffer on the stack
  ogs_pkbuf_t pkbuf;
  // Allocate memory for the data field
  pkbuf.data = malloc(PACKET_SIZE);
  if (!pkbuf.data) {
    perror("Failed to allocate memory for pkbuf->data");
    exit(EXIT_FAILURE);
  }

  // Simulate an IPv4 packet
  const char ipv4_packet[] = {0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00,
                              0x00, 0x40, 0x11, 0xb7, 0xe6, 0xc0, 0xa8,
                              0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};

  // Ensure the allocated size is sufficient for the packet
  if (sizeof(ipv4_packet) > PACKET_SIZE) {
    fprintf(stderr, "IPv4 packet size exceeds allocated buffer capacity\n");
    free(pkbuf.data); // Free allocated memory
    exit(EXIT_FAILURE);
  }

  // Copy the IPv4 packet data into the buffer
  memcpy(pkbuf.data, ipv4_packet, sizeof(ipv4_packet));
  pkbuf.len = sizeof(ipv4_packet);

  printf("Writing IPv4 packet to TUN interface...\n");

  // Write the packet to the TUN interface
  int result = ogs_tun_write(global_fd, &pkbuf);
  if (result != OGS_OK) {
    fprintf(stderr, "ogs_tun_write failed\n");
    exit(EXIT_FAILURE);
  }

  printf("ogs_tun_write passed.\n");
}

// Main test runner
int main(void) {
  printf("Running unit tests for ogs_tun_* functions...\n");

  // Initialize the test environment
  test_initialize();

  // Run individual tests
  // test_ogs_tun_write();
  // test_ogs_tun_read();

  // Finalize the test environment
  test_finalize();

  printf("All tests passed successfully!\n");
  return 0;
}
