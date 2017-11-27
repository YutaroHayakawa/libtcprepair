#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>

#include "libtcprepair.h"

/* length of fixed part of struct tcp_repair_state */
static const size_t fixed_part_len = offsetof(struct tcp_repair_state, recvq);

#define TCPOPT_MAXSEG 2
#define TCPOLEN_MAXSEG 4
#define TCPOPT_WINDOW 3
#define TCPOLEN_WINDOW 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10

#define TCP_REPAIR_QSIZE 0xFFFF

#define try(funccall) do { \
  int err; \
  err = funccall; \
  if (err) { \
    return err; \
  } \
} while (0);

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

static int tcp_repair_get_ack(int sock, struct tcp_repair_state *state) {
  socklen_t len = sizeof(uint32_t);
  return getsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ,
      &state->ack, &len);
}

static ssize_t tcp_repair_get_recvq(int sock, struct tcp_repair_state *state) {
  ssize_t size = recv(sock, state->recvq,
      TCP_REPAIR_QSIZE, MSG_PEEK | MSG_DONTWAIT);
  if (size <= 0) {
    if (errno != EAGAIN) {
      return size;
    } else {
      state->recvq_len = 0;
    }
  } else {
    state->recvq_len = size;
  }
  return 0;
}

static int tcp_repair_set_qstate_send(int sock) {
  return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_QUEUE,
      &(uint32_t){TCP_SEND_QUEUE}, sizeof(uint32_t));
}

static int tcp_repair_get_seq(int sock, struct tcp_repair_state *state) {
  socklen_t len = sizeof(uint32_t);
  return getsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ,
      &state->seq, &len);
}

static ssize_t tcp_repair_get_sendq(int sock, struct tcp_repair_state *state) {
  ssize_t size = recv(sock, state->sendq,
      TCP_REPAIR_QSIZE, MSG_PEEK | MSG_DONTWAIT);
  if (size <= 0) {
    if (errno != EAGAIN) {
      return size;
    } else {
      state->sendq_len = 0;
    }
  } else {
    state->sendq_len = size;
  }
  return 0;
}

static int tcp_repair_get_opt(int sock,
    struct tcp_repair_state *state, int code) {
  socklen_t len;

  switch (code) {
    case TCPOPT_MAXSEG: // mss
      len = TCPOLEN_MAXSEG;
      state->opt_mss.opt_code = TCPOPT_MAXSEG;
      return getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG,
          &state->opt_mss.opt_val, &len);
    default:
      return -1;
  }
}

static int tcp_repair_get_window(int sock, struct tcp_repair_state *state) {
  socklen_t slen = sizeof(struct tcp_repair_window);
  return getsockopt(sock, IPPROTO_TCP, TCP_REPAIR_WINDOW, &state->window, &slen);
}

static ssize_t tcp_repair_set_recvq(int sock, struct tcp_repair_state *state) {
  if (state->recvq_len > 0) {
    return send(sock, state->recvq, state->recvq_len, 0);
  }
  return 0;
}

static int tcp_repair_set_ack(int sock, struct tcp_repair_state *state) {
  return setsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ,
      &state->ack, sizeof(uint32_t));
}

static ssize_t tcp_repair_set_sendq(int sock, struct tcp_repair_state *state) {
  if (state->sendq_len > 0) {
    return send(sock, state->sendq, state->sendq_len, 0);
  }
  return 0;
}

static int tcp_repair_set_seq(int sock, struct tcp_repair_state *state) {
  return setsockopt(sock, IPPROTO_TCP, TCP_QUEUE_SEQ,
      &state->seq, sizeof(uint32_t));
}

static int tcp_repair_set_opt(int sock,
    struct tcp_repair_state *state, int code) {
  switch (code) {
    case TCPOPT_MAXSEG:
      return setsockopt(sock, IPPROTO_TCP, TCP_REPAIR_OPTIONS,
          &state->opt_mss, sizeof(struct tcp_repair_opt));
    default:
      return -1;
  }
}

static int tcp_repair_set_window(int sock, struct tcp_repair_state *state) {
  return setsockopt(sock, IPPROTO_TCP,
      TCP_REPAIR_WINDOW, &state->window, sizeof(struct tcp_repair_window));
}

static int tcp_repair_get_state(int sock, struct tcp_repair_state *state) {
  /* the order is essential */
  try(tcp_repair_start(sock));
  try(tcp_repair_set_qstate_recv(sock));
  try(tcp_repair_get_recvq(sock, state));
  try(tcp_repair_get_ack(sock, state));
  try(tcp_repair_set_qstate_send(sock));
  try(tcp_repair_get_sendq(sock, state));
  try(tcp_repair_get_seq(sock, state));
  try(tcp_repair_get_opt(sock, state, TCPOPT_MAXSEG));
  try(tcp_repair_get_window(sock, state));

  close(sock);

  return 0;
}

static int tcp_repair_set_state(int sock, struct tcp_repair_state *state,
    struct sockaddr_in *saddr, struct sockaddr_in *daddr) {
  /* the order is essential */
  try(tcp_repair_start(sock));

  try(tcp_repair_set_qstate_recv(sock));
  try(tcp_repair_set_recvq(sock, state));
  try(tcp_repair_set_ack(sock, state));
  try(tcp_repair_set_qstate_send(sock));
  try(tcp_repair_set_sendq(sock, state));
  try(tcp_repair_set_seq(sock, state));
  try(tcp_repair_set_window(sock, state));

  try(bind(sock, (struct sockaddr *)saddr, sizeof(struct sockaddr_in)));
  try(connect(sock, (struct sockaddr *)daddr, sizeof(struct sockaddr_in)));

  try(tcp_repair_set_opt(sock, state, TCPOPT_MAXSEG));

  try(tcp_repair_done(sock));

  return 0;
}

static ssize_t calculate_serialized_len(struct tcp_repair_state *state) {
  ssize_t ret = 0;

  ret += sizeof(uint32_t); // seq
  ret += sizeof(uint32_t); // ack
  ret += state->recvq_len;
  ret += state->sendq_len;
  ret += sizeof(struct tcp_repair_window);
  ret += sizeof(struct tcp_repair_opt);

  return ret;
}

struct tcp_repair_state *tcp_repair_init(void) {
  struct tcp_repair_state *ret;

  ret = calloc(sizeof(struct tcp_repair_state), 1);
  if (ret == NULL) {
    return NULL;
  }

  ret->recvq = calloc(TCP_REPAIR_QSIZE, 1);
  if (ret->recvq == NULL) {
    free(ret);
    return NULL;
  }

  ret->sendq = calloc(TCP_REPAIR_QSIZE, 1);
  if (ret->sendq == NULL) {
    free(ret->recvq);
    free(ret);
    return NULL;
  }

  return ret;
}

void tcp_repair_destroy(struct tcp_repair_state *state) {
  free(state->recvq);
  free(state->sendq);
  free(state);
}

int tcp_repair_extract_state(int sock, struct tcp_repair_state *state) {
  return tcp_repair_get_state(sock, state);
}

int tcp_repair_insert_state(int sock, struct tcp_repair_state *state,
    struct sockaddr_in *saddr, struct sockaddr_in *daddr) {
  return tcp_repair_set_state(sock, state, saddr, daddr);
}

ssize_t tcp_repair_serialize(struct tcp_repair_state *state, uint8_t *buf, ssize_t len) {
  ssize_t calc_len = calculate_serialized_len(state);

  if (buf == NULL) {
    return calc_len;
  }

  if (len < calc_len) {
    return -1;
  }

  memcpy(buf, state, fixed_part_len);
  memcpy(buf, state->recvq, state->recvq_len);
  memcpy(buf, state->sendq, state->sendq_len);

  return calc_len;
}

ssize_t tcp_repair_serialize_to_file(int fd, struct tcp_repair_state *state, ssize_t len) {
  ssize_t calc_len = calculate_serialized_len(state);

  if (len < calc_len) {
    return -1;
  }

  write(fd, state, fixed_part_len);
  write(fd, state->recvq, state->recvq_len);
  write(fd, state->sendq, state->sendq_len);

  return calc_len;
}

struct tcp_repair_state *tcp_repair_deserialize(uint8_t *buf) {
  struct tcp_repair_state *ret;

  ret = calloc(sizeof(struct tcp_repair_state), 1);
  if (ret == NULL) {
    return NULL;
  }

  struct tcp_repair_state *state = (struct tcp_repair_state *)buf;

  memcpy(ret, state, fixed_part_len);

  ret->recvq = calloc(state->recvq_len, 1);
  if (ret->recvq == NULL) {
    free(ret);
    return NULL;
  }
  memcpy(ret->recvq, state->recvq, state->recvq_len);

  ret->sendq = calloc(state->sendq_len, 1);
  if (ret->sendq == NULL) {
    free(ret->recvq);
    free(ret);
    return NULL;
  }
  memcpy(ret->sendq, state->recvq + state->recvq_len, state->sendq_len);

  return ret;
}

struct tcp_repair_state *tcp_repair_deserialize_from_file(int fd) {
  struct tcp_repair_state *ret;

  ret = calloc(sizeof(struct tcp_repair_state), 1);
  if (ret == NULL) {
    return NULL;
  }
  try(read(fd, ret, fixed_part_len));

  ret->recvq = calloc(ret->recvq_len, 1);
  if (ret->recvq == NULL) {
    free(ret);
    return NULL;
  }
  try(read(fd, ret->recvq, ret->recvq_len));

  ret->sendq = calloc(ret->sendq_len, 1);
  if (ret->sendq == NULL) {
    free(ret->recvq);
    free(ret);
    return NULL;
  }
  try(read(fd, ret->sendq, ret->sendq_len));

  return ret;
}
