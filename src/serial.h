#ifndef SERIAL_H
#define SERIAL_H

#include <stddef.h>
#include <stdint.h>

typedef intptr_t sp_t;

/* cfg is "PORT[,BAUD[,FRAME[,FLOW]]]", e.g. "COM3,115200,8N1,rtscts". Prints why and returns -1 on failure. */
int sp_open(sp_t *port, const char *cfg);

/* Neither blocks. Bytes moved (0 if none), or -1 on error. */
long sp_read(sp_t port, void *buf, size_t n);
long sp_write(sp_t port, const void *buf, size_t n);

/* 1: a stdin line (without newline) is in buf; 0: none yet; -1: stdin closed. Never blocks. */
int sp_stdin_line(char *buf, size_t n);

/* Sleep about 1 ms. */
void sp_idle(void);

#endif
