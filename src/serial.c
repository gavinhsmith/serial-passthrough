#include "serial.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cfg {
    char path[256];
    long baud;
    int data, stop, rtscts, xonxoff;
    char parity; /* N E O M S */
};

static int parse_cfg(const char *s, struct cfg *c)
{
    char buf[512], *tok[4] = {0}, *p = buf;
    int n;

    if (strlen(s) >= sizeof buf) goto bad;
    strcpy(buf, s);
    for (n = 0; n < 4 && p; n++) {
        tok[n] = p;
        if ((p = strchr(p, ','))) *p++ = '\0';
    }
    if (!*tok[0] || strlen(tok[0]) >= sizeof c->path) goto bad;
    strcpy(c->path, tok[0]);
    c->baud = 115200;
    c->data = 8;
    c->parity = 'N';
    c->stop = 1;
    c->rtscts = c->xonxoff = 0;
    if (tok[1] && *tok[1]) {
        char *end;
        c->baud = strtol(tok[1], &end, 10);
        if (*end || c->baud <= 0) goto bad;
    }
    if (tok[2] && *tok[2]) {
        const char *f = tok[2];
        int par = toupper((unsigned char)f[1]);
        if (strlen(f) != 3 || f[0] < '5' || f[0] > '8' || !strchr("NEOMS", par) || (f[2] != '1' && f[2] != '2'))
            goto bad;
        c->data = f[0] - '0';
        c->parity = (char)par;
        c->stop = f[2] - '0';
    }
    if (tok[3] && *tok[3]) {
        if (!strcmp(tok[3], "rtscts")) c->rtscts = 1;
        else if (!strcmp(tok[3], "xonxoff")) c->xonxoff = 1;
        else if (strcmp(tok[3], "none")) goto bad;
    }
    return 0;
bad:
    fprintf(stderr, "bad port '%s': expected PORT[,BAUD[,FRAME[,FLOW]]], e.g. COM3,115200,8N1,none\n", s);
    return -1;
}

#ifdef _WIN32

#include <windows.h>
#include <mmsystem.h>

static void win_err(const char *what)
{
    char msg[256] = "";
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, GetLastError(), 0, msg,
                   sizeof msg, NULL);
    msg[strcspn(msg, "\r\n")] = '\0';
    fprintf(stderr, "%s: %s\n", what, msg);
}

int sp_open(sp_t *port, const char *spec)
{
    /* Reads return at once; writes give up after ~1 ms and report the partial count. */
    COMMTIMEOUTS to = {MAXDWORD, 0, 0, 0, 1};
    struct cfg c;
    char name[300];
    HANDLE h;
    DCB d;

    if (parse_cfg(spec, &c)) return -1;
    snprintf(name, sizeof name, "%s%s", strncmp(c.path, "\\\\", 2) ? "\\\\.\\" : "", c.path);
    h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        win_err(c.path);
        return -1;
    }
    memset(&d, 0, sizeof d);
    d.DCBlength = sizeof d;
    if (!GetCommState(h, &d)) goto fail;
    d.BaudRate = (DWORD)c.baud;
    d.ByteSize = (BYTE)c.data;
    d.Parity = (BYTE)(strchr("NOEMS", c.parity) - "NOEMS"); /* NOPARITY..SPACEPARITY */
    d.fParity = c.parity != 'N';
    d.StopBits = c.stop == 2 ? TWOSTOPBITS : ONESTOPBIT;
    d.fBinary = 1;
    d.fNull = d.fErrorChar = d.fAbortOnError = 0;
    d.fOutxDsrFlow = d.fDsrSensitivity = 0;
    d.fDtrControl = DTR_CONTROL_ENABLE;
    d.fOutxCtsFlow = c.rtscts;
    d.fRtsControl = c.rtscts ? RTS_CONTROL_HANDSHAKE : RTS_CONTROL_ENABLE;
    d.fOutX = d.fInX = c.xonxoff;
    if (!SetCommState(h, &d) || !SetCommTimeouts(h, &to)) goto fail;
    timeBeginPeriod(1); /* so Sleep(1) sleeps ~1 ms, not ~15 */
    *port = (sp_t)h;
    return 0;
fail:
    win_err(c.path);
    CloseHandle(h);
    return -1;
}

long sp_read(sp_t port, void *buf, size_t n)
{
    DWORD got;
    if (!ReadFile((HANDLE)port, buf, (DWORD)n, &got, NULL)) {
        win_err("read");
        return -1;
    }
    return (long)got;
}

long sp_write(sp_t port, const void *buf, size_t n)
{
    DWORD put = 0;
    if (!WriteFile((HANDLE)port, buf, (DWORD)n, &put, NULL) && GetLastError() != ERROR_SEM_TIMEOUT) {
        win_err("write");
        return -1;
    }
    return (long)put;
}

/* Console handles can't be polled for whole lines, so a thread does the blocking fgets. */
static CRITICAL_SECTION lock;
static char line[4096];
static int line_state; /* 0 empty, 1 line waiting, -1 stdin closed */

static void hand_over(int state, const char *text)
{
    for (;;) {
        EnterCriticalSection(&lock);
        if (line_state == 0) {
            strcpy(line, text);
            line_state = state;
            LeaveCriticalSection(&lock);
            return;
        }
        LeaveCriticalSection(&lock);
        Sleep(1);
    }
}

static DWORD WINAPI stdin_thread(LPVOID arg)
{
    char buf[sizeof line];
    (void)arg;
    while (fgets(buf, sizeof buf, stdin)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        hand_over(1, buf);
    }
    hand_over(-1, "");
    return 0;
}

int sp_stdin_line(char *buf, size_t n)
{
    static int started;
    int r;
    if (!started) {
        InitializeCriticalSection(&lock);
        CreateThread(NULL, 0, stdin_thread, NULL, 0, NULL);
        started = 1;
    }
    EnterCriticalSection(&lock);
    if ((r = line_state) == 1) {
        snprintf(buf, n, "%s", line);
        line_state = 0;
    }
    LeaveCriticalSection(&lock);
    return r;
}

void sp_idle(void)
{
    Sleep(1);
}

#else

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static int set_speed(struct termios *t, long baud)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    return cfsetispeed(t, (speed_t)baud) || cfsetospeed(t, (speed_t)baud); /* BSD speeds are plain numbers */
#else
    static const struct { long baud; speed_t s; } rates[] = {
        {50, B50}, {75, B75}, {110, B110}, {134, B134}, {150, B150}, {200, B200}, {300, B300},
        {600, B600}, {1200, B1200}, {1800, B1800}, {2400, B2400}, {4800, B4800}, {9600, B9600},
        {19200, B19200}, {38400, B38400}, {57600, B57600}, {115200, B115200}, {230400, B230400},
#ifdef B921600
        {460800, B460800}, {921600, B921600},
#endif
#ifdef B4000000
        {500000, B500000}, {576000, B576000}, {1000000, B1000000}, {1500000, B1500000},
        {2000000, B2000000}, {3000000, B3000000}, {4000000, B4000000},
#endif
    };
    for (size_t i = 0; i < sizeof rates / sizeof *rates; i++)
        if (rates[i].baud == baud) return cfsetispeed(t, rates[i].s) || cfsetospeed(t, rates[i].s);
    return -1;
#endif
}

int sp_open(sp_t *port, const char *spec)
{
    struct termios t;
    struct cfg c;
    int fd;

    if (parse_cfg(spec, &c)) return -1;
    fd = open(c.path, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0 || tcgetattr(fd, &t)) goto fail;
    cfmakeraw(&t);
    t.c_cflag &= ~(tcflag_t)(CSIZE | PARENB | PARODD | CSTOPB | CRTSCTS);
    t.c_cflag |= CLOCAL | CREAD | (c.data == 5 ? CS5 : c.data == 6 ? CS6 : c.data == 7 ? CS7 : CS8);
    if (c.parity != 'N') t.c_cflag |= PARENB | (c.parity == 'O' || c.parity == 'M' ? PARODD : 0);
#ifdef CMSPAR
    t.c_cflag &= ~(tcflag_t)CMSPAR;
    if (c.parity == 'M' || c.parity == 'S') t.c_cflag |= CMSPAR;
#else
    if (c.parity == 'M' || c.parity == 'S') {
        fprintf(stderr, "%s: mark/space parity is not supported on this OS\n", c.path);
        close(fd);
        return -1;
    }
#endif
    if (c.stop == 2) t.c_cflag |= CSTOPB;
    if (c.rtscts) t.c_cflag |= CRTSCTS;
    t.c_iflag &= ~(tcflag_t)(IXON | IXOFF | IXANY);
    if (c.xonxoff) t.c_iflag |= IXON | IXOFF;
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    if (set_speed(&t, c.baud)) {
        fprintf(stderr, "%s: unsupported baud rate %ld\n", c.path, c.baud);
        close(fd);
        return -1;
    }
    if (tcsetattr(fd, TCSANOW, &t)) goto fail;
    *port = fd;
    return 0;
fail:
    fprintf(stderr, "%s: %s\n", c.path, strerror(errno));
    if (fd >= 0) close(fd);
    return -1;
}

static long nonblock(long r, const char *what)
{
    if (r >= 0) return r;
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
    perror(what);
    return -1;
}

long sp_read(sp_t port, void *buf, size_t n)
{
    return nonblock((long)read((int)port, buf, n), "read");
}

long sp_write(sp_t port, const void *buf, size_t n)
{
    return nonblock((long)write((int)port, buf, n), "write");
}

int sp_stdin_line(char *buf, size_t n)
{
    static char acc[4096];
    static size_t len;
    static int eof;
    struct pollfd p = {0, POLLIN, 0};
    char *nl;
    size_t l;

    while (!(nl = memchr(acc, '\n', len)) && !eof && len < sizeof acc && poll(&p, 1, 0) > 0) {
        ssize_t r = read(0, acc + len, sizeof acc - len);
        if (r <= 0) eof = 1;
        else len += (size_t)r;
    }
    if (!nl && !eof && len < sizeof acc) return 0;
    if (!nl && !len) return -1;
    l = nl ? (size_t)(nl - acc) : len; /* unterminated last line (or overlong line) goes out as is */
    snprintf(buf, n, "%.*s", (int)(l && acc[l - 1] == '\r' ? l - 1 : l), acc);
    len -= l + (nl != NULL);
    memmove(acc, acc + l + (nl != NULL), len);
    return 1;
}

void sp_idle(void)
{
    struct timespec d = {0, 1000000};
    nanosleep(&d, NULL);
}

#endif
