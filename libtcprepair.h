#pragma once

struct tcp_repair_state;

extern struct tcp_repair_state *tcp_repair_init(void);
extern void tcp_repair_destroy(struct tcp_repair_state *state);
extern int tcp_repair_extract_state(int sock, struct tcp_repair_state *state);
extern int tcp_repair_insert_state(int sock, struct tcp_repair_state *state,
    struct sockaddr_in *saddr, struct sockaddr_in *daddr);
extern ssize_t tcp_repair_serialize(struct tcp_repair_state *state, uint8_t *buf, ssize_t len);
extern struct tcp_repair_state *tcp_repair_deserialize(uint8_t *buf);
