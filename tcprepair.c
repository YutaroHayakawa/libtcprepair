#include <errno.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <tcprepair.h>

#define TCPOPT_MAXSEG 2
#define TCPOLEN_MAXSEG 4
#define TCPOPT_WINDOW 3
#define TCPOLEN_WINDOW 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10

/* dummy buf for get queue length */
static uint8_t __dummy_buf[0xFFFF];

static int tcp_repair_start(int sock) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR, &(int){1}, sizeof(int));
}

static int tcp_repair_done(int sock) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR, &(int){0}, sizeof(int));
}

static int tcp_repair_set_qstate_recv(int sock) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_QUEUE,
                    &(uint32_t){TCP_RECV_QUEUE}, sizeof(uint32_t));
}

static int tcp_repair_get_ack(int sock, uint32_t *ack) {
  socklen_t len = sizeof(uint32_t);
  return getsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, ack, &len);
}

static ssize_t tcp_repair_get_recvq(int sock, uint8_t *buf, size_t len) {
  ssize_t size = recv(sock, buf, len, MSG_PEEK | MSG_DONTWAIT);
  if (size < 0) {
    if (errno != EAGAIN) {
      return size;
    } else {
      return 0;
    }
  }
  return size;
}

static int tcp_repair_get_recvq_len(int sock, size_t *rlen) {
  ssize_t size = recv(sock, __dummy_buf, 0xFFFF, MSG_PEEK | MSG_DONTWAIT);
  if (size <= 0) {
    if (errno == EAGAIN || size == 0) {
      *rlen = 0;
      return 0;
    } else {
      return -1;
    }
  }
  *rlen = size;
  return 0;
}

static int tcp_repair_set_qstate_send(int sock) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_QUEUE,
                    &(uint32_t){TCP_SEND_QUEUE}, sizeof(uint32_t));
}

static int tcp_repair_get_seq(int sock, uint32_t *seq) {
  socklen_t len = sizeof(uint32_t);
  return getsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, seq, &len);
}

static int tcp_repair_get_sendq_len(int sock, size_t *slen) {
  ssize_t size = recv(sock, __dummy_buf, 0xFFFF, MSG_PEEK | MSG_DONTWAIT);
  if (size <= 0) {
    if (errno == EAGAIN || size == 0) {
      *slen = 0;
      return 0;
    } else {
      return -1;
    }
  }
  *slen = size;
  return 0;
}

static ssize_t tcp_repair_get_sendq(int sock, uint8_t *buf, size_t len) {
  ssize_t size = recv(sock, buf, len, MSG_PEEK | MSG_DONTWAIT);
  if (size < 0) {
    if (errno != EAGAIN) {
      return size;
    } else {
      return 0;
    }
  }
  return size;
}

static int tcp_repair_get_opt(int sock, struct tcp_repair_opt *opt, int code) {
  socklen_t len;

  switch (code) {
    case TCPOPT_MAXSEG:  // mss
      len = TCPOLEN_MAXSEG;
      opt->opt_code = TCPOPT_MAXSEG;
      return getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &opt->opt_val, &len);
    default:
      return -1;
  }
}

static int tcp_repair_get_window(int sock, struct tcp_repair_window *window) {
  socklen_t slen = sizeof(struct tcp_repair_window);
  return getsockopt(sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, window, &slen);
}

static ssize_t tcp_repair_set_recvq(int sock, uint8_t *buf, size_t len) {
  return send(sock, buf, len, 0);
}

static int tcp_repair_set_ack(int sock, uint32_t *ack) {
  return setsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, ack, sizeof(uint32_t));
}

static ssize_t tcp_repair_set_sendq(int sock, uint8_t *buf, size_t len) {
  return send(sock, buf, len, 0);
}

static int tcp_repair_set_seq(int sock, uint32_t *seq) {
  return setsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ, seq, sizeof(uint32_t));
}

static int tcp_repair_set_opt(int sock, struct tcp_repair_opt *opt, int code) {
  switch (code) {
    case TCPOPT_MAXSEG:
      return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_OPTIONS, opt,
                        sizeof(struct tcp_repair_opt));
    default:
      return -1;
  }
}

static int tcp_repair_set_window(int sock, struct tcp_repair_window *window) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, window,
                    sizeof(struct tcp_repair_window));
}

ssize_t tcp_repair_serialize_to_mem(int sock, uint8_t **buf,
    uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport) {
  int err;
  size_t recvq_len, sendq_len;

#define try1(funccall)        \
  if ((err = funccall) < 0) { \
    goto catch1;              \
  }
#define try2(funccall)        \
  if ((err = funccall) < 0) { \
    goto catch2;              \
  }

  try1(tcp_repair_start(sock));
  try2(tcp_repair_set_qstate_recv(sock));
  try1(tcp_repair_get_recvq_len(sock, &recvq_len));
  try2(tcp_repair_set_qstate_send(sock));
  try1(tcp_repair_get_sendq_len(sock, &sendq_len));

  *buf = malloc(sizeof(struct tcp_repair_serialize_format) + recvq_len + sendq_len);
  if (*buf == NULL) {
    tcp_repair_done(sock);
    return -1;
  }

  struct tcp_repair_serialize_format *format =
    (struct tcp_repair_serialize_format *)*buf;

  format->saddr = saddr;
  format->sport = sport;
  format->daddr = daddr;
  format->dport = dport;

  format->recvq_len = recvq_len;
  format->sendq_len = sendq_len;

  try2(tcp_repair_get_opt(sock, &format->opt_mss, TCPOPT_MAXSEG));
  try2(tcp_repair_get_window(sock, &format->window));

  try2(tcp_repair_set_qstate_recv(sock));
  try2(tcp_repair_get_recvq(sock,
                            *buf + sizeof(struct tcp_repair_serialize_format),
                            format->recvq_len));
  try2(tcp_repair_get_ack(sock, &format->ack));

  try2(tcp_repair_set_qstate_send(sock));
  try2(tcp_repair_get_sendq(
      sock,
      *buf + sizeof(struct tcp_repair_serialize_format) + format->recvq_len,
      format->sendq_len));
  try2(tcp_repair_get_seq(sock, &format->seq));

  close(sock);

#undef try1
#undef try2

  return sizeof(struct tcp_repair_serialize_format) + recvq_len + sendq_len;

catch1:
  return err;
catch2:
  free(*buf);
  return err;
}

int tcp_repair_deserialize_from_mem(uint8_t *buf, size_t *size) {
  int err;
  int sock;

#define try1(funccall)        \
  if ((err = funccall) < 0) { \
    goto catch1;              \
  }

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return sock;
  }

  try1(tcp_repair_start(sock));

  struct tcp_repair_serialize_format *format =
      (struct tcp_repair_serialize_format *)buf;

  try1(tcp_repair_set_qstate_recv(sock));
  if (format->recvq_len > 0) {
    try1(tcp_repair_set_recvq(sock, buf +
          sizeof(struct tcp_repair_serialize_format),
          format->recvq_len));
  }
  try1(tcp_repair_set_ack(sock, &format->ack));

  try1(tcp_repair_set_qstate_send(sock));
  if (format->sendq_len > 0) {
    try1(tcp_repair_set_sendq(sock, buf +
          sizeof(struct tcp_repair_serialize_format) +
          format->recvq_len, format->sendq_len));
  }
  try1(tcp_repair_set_seq(sock, &format->seq));

  try1(tcp_repair_set_window(sock, &format->window));

  struct sockaddr_in saddr;
  saddr.sin_family = AF_INET;
  saddr.sin_addr.s_addr = format->saddr;
  saddr.sin_port = format->sport;
  try1(bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)));

  struct sockaddr_in daddr;
  daddr.sin_family = AF_INET;
  daddr.sin_addr.s_addr = format->daddr;
  daddr.sin_port = format->dport;
  try1(connect(sock, (struct sockaddr *)&daddr, sizeof(struct sockaddr_in)));

  try1(tcp_repair_set_opt(sock, &format->opt_mss, TCPOPT_MAXSEG));
  try1(tcp_repair_done(sock));

  *size = sizeof(struct tcp_repair_serialize_format) +
    format->sendq_len + format->recvq_len;

  return sock;

#undef try1

catch1:
  return err;
}
