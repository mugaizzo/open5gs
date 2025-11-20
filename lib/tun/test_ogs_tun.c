#include "ogs-core.h"
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

// Helper function to get current time in microseconds
static long long get_time_usec(void) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return ((long long)tv.tv_sec * 1000000LL) + tv.tv_usec;
}

// Initialize the test environment by opening the TUN interface
static void test_initialize(void) {
  printf("Initializing test environment...\n");

  long long start_time = get_time_usec();
  global_fd = ogs_tun_open((char *)TEST_IFNAME, strlen(TEST_IFNAME), 0);
  long long end_time = get_time_usec();
  long long delay_usec = end_time - start_time;
  assert(global_fd != INVALID_SOCKET);
  printf("ogs_tun_open passed. File descriptor: %d\n", global_fd);
  printf("Open delay: %lld microseconds\n", delay_usec);
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
  long long start_time = get_time_usec();
  ogs_pkbuf_t *recvbuf = ogs_tun_read(global_fd, packet_pool);
  long long end_time = get_time_usec();
  long long delay_usec = end_time - start_time;

  if (!recvbuf) {
    fprintf(stderr,
            "ogs_tun_read failed: No data received or error occurred\n");
    return;
  }
  // Print the received packet data
  printf("[RECEIVED] Packet length: %d\n", recvbuf->len);
  printf("Read delay: %lld microseconds\n", delay_usec);
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
  // const char ipv4_packet[] = {0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00,
  //                             0x00, 0x40, 0x11, 0xb7, 0xe6, 0xc0, 0xa8,
  //                             0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7};

  const char ipv4_packet[] = {
      // IP Header (20 bytes)
      0x45, 0x00, 0x00, 0x3c, // Version, IHL, Type of Service, Total Length
      0x13, 0x54, 0x40, 0x00, // Identification, Flags, Fragment Offset
      0x40, 0x01, 0x70, 0x62, // TTL, Protocol (ICMP), Header Checksum
      0xc0, 0xa8, 0x01, 0x4a, // Source IP (192.168.1.74)
      0xc0, 0xa8, 0x01, 0x01, // Destination IP (192.168.1.1)

      // ICMP Header (8 bytes) + Data (32 bytes)
      0x08, 0x00, 0x5e, 0x63, // Type (Echo Request), Code, Checksum
      0x00, 0x01, 0x00, 0x01, // Identifier, Sequence Number
      0x61, 0x62, 0x63, 0x64, // Data payload ("abcd...")
      0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70,
      0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65,
      0x66, 0x67, 0x68, 0x69};
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
  long long start_time = get_time_usec();
  int result = ogs_tun_write(global_fd, &pkbuf);
  long long end_time = get_time_usec();
  long long delay_usec = end_time - start_time;

  if (result != OGS_OK) {
    fprintf(stderr, "ogs_tun_write failed\n");
    exit(EXIT_FAILURE);
  }

  printf("ogs_tun_write passed.\n");
  printf("Write delay: %lld microseconds\n", delay_usec);
}

// Main test runner
int main(void) {
  printf("Running unit tests for ogs_tun_* functions...\n");

  // Initialize the test environment
  test_initialize();

  // Run individual tests
  test_ogs_tun_write();
  test_ogs_tun_read();
  // Finalize the test environment
  test_finalize();

  printf("All tests passed successfully!\n");
  return 0;
}
