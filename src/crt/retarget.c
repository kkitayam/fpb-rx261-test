/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Koji KITAYAMA */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <reent.h>
#include <unistd.h>
#include "uart.h"

/* close */
int _close_r(struct _reent *r, int fd)
{
    (void)fd;
    r->_errno = EBADF;
    return -1;
}

/* fstat */
int _fstat_r(struct _reent *r, int fd, struct stat *st)
{
    (void)fd;
    (void)st;
    r->_errno = EBADF;
    return -1;
}

/* isatty */
int _isatty_r(struct _reent *r, int fd)
{
    (void)fd;
    r->_errno = EBADF;
    return 0; /* isatty naturally returns 0 for "false" */
}

/* lseek */
off_t _lseek_r(struct _reent *r, int fd, off_t offset, int whence)
{
    (void)fd;
    (void)offset;
    (void)whence;
    r->_errno = EBADF;
    return (off_t)-1;
}

/* read */
ssize_t _read_r(struct _reent *r, int fd, void *buf, size_t cnt)
{
    (void)fd;
    (void)buf;
    (void)cnt;
    r->_errno = EBADF;
    return -1;
}

/* write */
ssize_t _write_r(struct _reent *r, int fd, const void *buf, size_t cnt)
{
    (void)r;

    /* Typically only accept stdout / stderr */
    if (fd != STDOUT_FILENO && fd != STDERR_FILENO) {
        r->_errno = EBADF;
        return -1;
    }

    const char *p = (const char *)buf;
    for (size_t i = 0; i < cnt; i++) {
        /* convert newline to carriage return (optional) */
        if (p[i] == '\n') {
            uart_putc('\r');
        }
        uart_putc(p[i]);
    }

    return cnt;
}

/* sbrk */
void *_sbrk_r(struct _reent *r, ptrdiff_t incr)
{
    (void)incr;
    r->_errno = ENOMEM;
    return (void *)-1;
}
