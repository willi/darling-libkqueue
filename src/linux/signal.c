/*
 * Copyright (c) 2009 Mark Heily <mark@heily.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "private.h"

#ifdef DARLING
#include <sys/eventfd.h>
#include <darling/emulation/linux_premigration/signal/signal_knotes.h>
#endif

#if HAVE_SYS_SIGNALFD_H
# include <sys/signalfd.h>
#else
#define signalfd(a,b,c) syscall(SYS_signalfd, (a), (b), (c))
#define SFD_NONBLOCK 04000
struct signalfd_siginfo
{
  uint32_t ssi_signo;
  int32_t ssi_errno;
  int32_t ssi_code;
  uint32_t ssi_pid;
  uint32_t ssi_uid;
  int32_t ssi_fd;
  uint32_t ssi_tid;
  uint32_t ssi_band;
  uint32_t ssi_overrun;
  uint32_t ssi_trapno;
  int32_t ssi_status;
  int32_t ssi_int;
  uint64_t ssi_ptr;
  uint64_t ssi_utime;
  uint64_t ssi_stime;
  uint64_t ssi_addr;
  uint8_t __pad[48];
};
#endif

#ifndef DARLING
static void
signalfd_reset(int sigfd)
{
    struct signalfd_siginfo sig;
    ssize_t n;

    /* Discard any pending signal */
    n = read(sigfd, &sig, sizeof(sig));
    if (n < 0 || n != sizeof(sig)) {
        if (errno == EWOULDBLOCK)
            return;
        //FIXME: eintr?
        dbg_perror("read(2) from signalfd");
        abort();
    }
}

#endif /* !DARLING */

static int
signalfd_add(int epfd, int sigfd, void *ptr)
{
    struct epoll_event ev;
    int rv;

    /* Add the signalfd to the kqueue's epoll descriptor set */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = ptr;
    rv = epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);
    if (rv < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }

    return (0);
}

#ifndef DARLING
static int
signalfd_create(int epfd, void *ptr, int signum)
{
    static int flags = SFD_NONBLOCK;
    sigset_t sigmask;
    int sigfd;

    /* Create a signalfd */
    sigemptyset(&sigmask);
    sigaddset(&sigmask, signum);
    sigfd = signalfd(-1, &sigmask, flags);

    /* WORKAROUND: Flags are broken on kernels older than Linux 2.6.27 */
    if (sigfd < 0 && errno == EINVAL && flags != 0) {
        flags = 0;
        sigfd = signalfd(-1, &sigmask, flags);
    }
    if (sigfd < 0) {
        dbg_perror("signalfd(2)");
        goto errout;
    }
    fcntl(sigfd, F_SETFD, FD_CLOEXEC);

    /* Block the signal handler from being invoked */
    if (sigprocmask(SIG_BLOCK, &sigmask, NULL) < 0) {
        dbg_perror("sigprocmask(2)");
        goto errout;
    }

    signalfd_reset(sigfd);

    if (signalfd_add(epfd, sigfd, ptr) < 0)
        goto errout;

    dbg_printf("added sigfd %d to epfd %d (signum=%d)", sigfd, epfd, signum);

    return (sigfd);

errout:
    (void) __close_for_kqueue(sigfd);
    return (-1);
}
#endif /* !DARLING */

#ifdef DARLING
/*
 * Darling's processes don't block signals on every thread, which a signalfd needs, and XNU records signals whatever
 * their disposition anyway. Instead, each knote has an eventfd, which Darling's signal handler adds 1 to whenever it
 * delivers the signal (see signal_knotes.h).
 */
static int
signal_eventfd_create(int epfd, void *ptr, int signum)
{
    int fd, rv;

    fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (fd < 0) {
        dbg_perror("eventfd(2)");
        return (-1);
    }
    rv = __darling_signal_knote_register(signum, fd);
    if (rv < 0) {
        errno = (rv == -22) ? EINVAL : ENOSPC;
        goto errout;
    }
    if (signalfd_add(epfd, fd, ptr) < 0) {
        __darling_signal_knote_unregister(fd);
        goto errout;
    }
    return (fd);

errout:
    (void) __close_for_kqueue(fd);
    return (-1);
}

int
evfilt_signal_copyout(struct kevent64_s *dst, struct knote *src, void *x UNUSED)
{
    eventfd_t count = 0;

    kevent_int_to_64(&src->kev, dst);
    /* the number of times the signal was delivered since the knote last fired, as XNU reports */
    if (eventfd_read(src->kdata.kn_signalfd, &count) < 0 || count == 0)
        count = 1;
    dst->data = count;

    return (0);
}

#else /* !DARLING */
int
evfilt_signal_copyout(struct kevent64_s *dst, struct knote *src, void *x UNUSED)
{
    int sigfd;

    sigfd = src->kdata.kn_signalfd;

    signalfd_reset(sigfd);

    kevent_int_to_64(&src->kev, dst);
    /* NOTE: dst->data should be the number of times the signal occurred,
       but that information is not available.
     */
    dst->data = 1;  

    return (0);
}
#endif /* DARLING */

int
evfilt_signal_knote_create(struct filter *filt, struct knote *kn)
{
    int fd;

#ifdef DARLING
    fd = signal_eventfd_create(filter_epfd(filt), kn, kn->kev.ident);
#else
    fd = signalfd_create(filter_epfd(filt), kn, kn->kev.ident);
#endif
    if (fd > 0) {
        kn->kev.flags |= EV_CLEAR;
        kn->kdata.kn_signalfd = fd;
        return (0);
    } else {
        kn->kdata.kn_signalfd = -1;
        return (-1);
    }
}

int
evfilt_signal_knote_modify(struct filter *filt UNUSED, 
        struct knote *kn UNUSED, 
        const struct kevent64_s *kev UNUSED)
{
    /* Nothing to do since the signal number does not change. */

    return (0);
}

int
evfilt_signal_knote_delete(struct filter *filt, struct knote *kn)
{
    const int sigfd = kn->kdata.kn_signalfd;

    /* Needed so that delete() can be called after disable() */
    if (kn->kdata.kn_signalfd == -1)
        return (0);

#ifdef DARLING
    /* before the descriptor closes: no signal handler writes to it after this */
    __darling_signal_knote_unregister(sigfd);
#endif

    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_DEL, sigfd, NULL) < 0) {
#ifdef DARLING
        /* a disabled knote's eventfd is already out of the epoll set */
        if (errno != ENOENT)
#endif
        {
            dbg_perror("epoll_ctl(2)");
            return (-1);
        }
    }

    if (__close_for_kqueue(sigfd) < 0) {
        dbg_perror("close(2)");
        return (-1);
    }

    /* NOTE: This does not call sigprocmask(3) to unblock the signal. */
    kn->kdata.kn_signalfd = -1;

    return (0);
}

#ifdef DARLING
/*
 * A disabled knote keeps counting the signal, as XNU's does, and fires once enabled again if it arrived meanwhile:
 * libdispatch disables a signal source's knote while its handler runs (EV_DISPATCH).
 */
int
evfilt_signal_knote_enable(struct filter *filt, struct knote *kn)
{
    dbg_printf("enabling ident %u", (unsigned int) kn->kev.ident);
    return signalfd_add(filter_epfd(filt), kn->kdata.kn_signalfd, kn);
}

int
evfilt_signal_knote_disable(struct filter *filt, struct knote *kn)
{
    dbg_printf("disabling ident %u", (unsigned int) kn->kev.ident);
    if (epoll_ctl(filter_epfd(filt), EPOLL_CTL_DEL, kn->kdata.kn_signalfd, NULL) < 0) {
        dbg_perror("epoll_ctl(2)");
        return (-1);
    }
    return (0);
}
#else
int
evfilt_signal_knote_enable(struct filter *filt, struct knote *kn)
{
    dbg_printf("enabling ident %u", (unsigned int) kn->kev.ident);
    return evfilt_signal_knote_create(filt, kn);
}

int
evfilt_signal_knote_disable(struct filter *filt, struct knote *kn)
{
    dbg_printf("disabling ident %u", (unsigned int) kn->kev.ident);
    return evfilt_signal_knote_delete(filt, kn);
}
#endif


const struct filter evfilt_signal = {
    EVFILT_SIGNAL,
    NULL,
    NULL,
    evfilt_signal_copyout,
    evfilt_signal_knote_create,
    evfilt_signal_knote_modify,
    evfilt_signal_knote_delete,
    evfilt_signal_knote_enable,
    evfilt_signal_knote_disable,         
};
