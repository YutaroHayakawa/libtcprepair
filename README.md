# libtcprepair

Mini library for Linux TCP\_REPAIR

## Usage

**Basic**
```
/* create socket in here */

struct tcp_repair_state *state = tcp_repair_init();

error = tcp_repair_extract_state(original_socket, state);
if (error) {
  /* error */
}

/* create new socket in here */

error = tcp_repair_insert_state(new_socket, state, src_sockaddr, dst_sockaddr);
if (error) {
  /* error */
}

tcp_repair_destroy(state);
```

**Serialize/Deserialize TCP state**
```
/* after tcp_repair_extrace_state ... */

// calculate length of serialized TCP state */
ssize_t len = tcp_repair_serialize(state, NULL, 0);

uint8_t *buf = calloc(len, 1);
if (buf == NULL) {
  /* error */
}

// serialize
len = tcp_repair_serialize(state, buf, len);
if (len < 0) {
  /* error */
}

// deserialize
struct tcp_repair_state *state  = tcp_repair_deserialize(buf);
if (state == NULL) {
  /* error */
}
```
