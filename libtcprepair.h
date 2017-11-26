#pragma once

struct tcp_repair_state {
  uint32_t seq;
  uint32_t ack;
  uint64_t recvq_len;
  uint64_t sendq_len;
  struct tcp_repair_window window;
  struct tcp_repair_opt opt_mss;
  uint8_t *recvq;
  uint8_t *sendq;
};


extern struct tcp_repair_state *tcp_repair_init(void);
extern void tcp_repair_destroy(struct tcp_repair_state *state);
extern int tcp_repair_extract_state(int sock, struct tcp_repair_state *state);
extern int tcp_repair_insert_state(int sock, struct tcp_repair_state *state,
    struct sockaddr_in *saddr, struct sockaddr_in *daddr);
extern ssize_t tcp_repair_serialize(struct tcp_repair_state *state, uint8_t *buf, ssize_t len);
extern struct tcp_repair_state *tcp_repair_deserialize(uint8_t *buf);
