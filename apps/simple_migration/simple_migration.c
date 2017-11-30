/*
 * Simple migration server program. Please use telnet for client
 */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdnoreturn.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/tcp.h>

#include <tcprepair.h>

noreturn void die(const char *msg) {
  perror(msg);
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  int err;

  char *listen_addr;
  uint16_t listen_port;
  if (argc < 3) {
    listen_addr = strdup("127.0.0.1");
    listen_port = 12345;
  } else {
    listen_addr = strdup(argv[1]);
    listen_port = atoi(argv[2]);
  }

  int lsock = socket(AF_INET, SOCK_STREAM, 0);
  if (lsock < 0) {
    die("socket");
  }

  if (listen_port < 0) {
    fprintf(stderr, "Error: Invalid port number!\n");
    exit(EXIT_FAILURE);
  }

  err = setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
  if (err < 0) {
    die("setsockopt");
  }

  struct sockaddr_in laddr;
  laddr.sin_family = AF_INET;
  laddr.sin_addr.s_addr = inet_addr(listen_addr);
  laddr.sin_port = htons((uint16_t)listen_port);

  err = bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr));
  if (err < 0) {
    die("bind");
  }

  listen(lsock, 100);

  printf("Listening on %s:%d ...\n", listen_addr, listen_port);

  int csock;
  struct sockaddr_in caddr;
  socklen_t clen = sizeof(caddr);

  csock = accept(lsock, (struct sockaddr *)&caddr, &clen);
  if (csock < 0) {
    die("accept");
  }

  const char *msg1 = "I will migrate from now ...\n";
  ssize_t wlen = write(csock, msg1, strlen(msg1));
  if (wlen < 0) {
    die("write");
  }

  /* Serialize tcp state. Memory for store it automatically allocated */
  uint8_t *buf;
  ssize_t buf_size = tcp_repair_serialize_to_mem(csock, &buf, inet_addr(listen_addr),
      htons(listen_port), caddr.sin_addr.s_addr, caddr.sin_port);
  if (buf_size < 0) {
    die("prism_transport_export_to_mem");
  }

  /*
   * Note that in here, csock is already closed and not a valid
   * socket anymore. Don't use it!
   */

  int new_sock = tcp_repair_deserialize_from_mem(buf);
  if (new_sock < 0) {
    die("tcp_repair_deserialize_from_mem");
  }

  const char *msg2 = "Migrated!\n";
  wlen = write(new_sock, msg2, strlen(msg2));
  if (wlen < 0) {
    die("write");\
  }

  free(listen_addr);
  close(lsock);

  /* We need to free these */
  free(buf);
  close(new_sock);

  return EXIT_SUCCESS;
}
