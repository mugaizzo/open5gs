#include "host_tun_service.h"
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define TUN_DEVICE "/dev/net/tun"

int host_tun_open(const char *ifname, int is_tap, int *tun_fd) {
  struct ifreq ifr;
  int fd;

  // Open the TUN/TAP device file
  fd = open(TUN_DEVICE, O_RDWR);
  if (fd < 0) {
    perror("Failed to open /dev/net/tun");
    return -1;
  }

  // Configure the TUN/TAP interface
  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = is_tap ? IFF_TAP : IFF_TUN;
  ifr.ifr_flags |= IFF_NO_PI; // Disable packet information

  if (ifname && *ifname) {
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1); // Set the interface name
  }

  if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
    perror("Failed to configure TUN/TAP interface");
    close(fd);
    return -1;
  }

  // Return the file descriptor for the TUN device
  *tun_fd = fd;
  return 0;
}

int host_tun_close(int tun_fd) {
  if (close(tun_fd) < 0) {
    perror("Failed to close TUN device");
    return -1;
  }
  return 0;
}
