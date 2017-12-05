#pragma once

#include <linux/tcp.h>

struct tcp_repair_serialize_format {
  uint32_t saddr;
  uint16_t sport;
  uint32_t daddr;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint64_t recvq_len;
  uint64_t sendq_len;
  struct tcp_repair_window window;
  struct tcp_repair_opt opt_mss;
  // send queue
  // recv queue
}__attribute__((packed));

extern ssize_t tcp_repair_serialize_to_mem(int sock, uint8_t **buf, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
extern int tcp_repair_deserialize_from_mem(uint8_t *buf, size_t *size);
extern ssize_t tcp_repair_serialize_to_mem2(int sock, uint8_t *buf, uint32_t saddr, uint16_t sport, uint32_t daddr, uint16_t dport);
