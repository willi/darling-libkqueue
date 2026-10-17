/*
 * EVFILT_SOCK, XNU's socket event filter (bsd/kern/uipc_socket.c: filt_sockattach, filt_sockev_common,
 * filt_socktouch, filt_sockprocess). Apple's Network.framework learns from it that a nonblocking connect()
 * completed (NOTE_CONNECTED), failed or was reset (NOTE_CONNRESET), timed out (NOTE_TIMEOUT) or that a direction was
 * shut down (NOTE_READCLOSED, NOTE_WRITECLOSED); libdispatch's DISPATCH_SOURCE_TYPE_SOCK registers it.
 *
 * XNU raises the filter from the socket's state changes (soevent() hints) and computes what it reports from the
 * socket's state (so_state) and pending error (so_error). Here, Linux wakes the knote: epoll watches a copy of the
 * socket, edge-triggered, for the readiness Linux changes when the socket's state does (a connect completing or
 * failing, a shutdown, a reset, an error). Darling's libsystem_kernel derives XNU's state and error from the Linux
 * socket (_socket_state_4libkqueue), and the knote turns them into notes as filt_sockev_common does:
 * - level-triggered notes (NOTE_CONNECTED, NOTE_DISCONNECTED, NOTE_READCLOSED, NOTE_WRITECLOSED, NOTE_RESUME) are
 *   reported while their state holds, but wake the program only once;
 * - XNU's one-shot hints come from the state changes that raise them: a new error is a reset (ECONNREFUSED,
 *   ECONNRESET: NOTE_CONNRESET) or a timeout (ETIMEDOUT, and the unreachable errors XNU's TCP reports when its
 *   retransmissions time out: NOTE_TIMEOUT); connecting or disconnecting updates TCP's connection info
 *   (NOTE_CONNINFO_UPDATED);
 * - a pending error fires the knote with EV_EOF and the error as data, and stays pending for the program's SO_ERROR;
 * - data is otherwise SOCKEV_CONNECTED / SOCKEV_DISCONNECTED.
 * Sockets are never suspended (XNU suspends them for interface flow control), so NOTE_RESUME holds.
 *
 * An eventfd wakes the knote outside the socket's own events: when attaching or updating it finds something to
 * report, and after a delivery without EV_CLEAR, which XNU re-evaluates on the next kevent().
 *
 * Not reported: NOTE_NOSRCADDR, NOTE_IFDENIED, NOTE_KEEPALIVE, NOTE_ADAPTIVE_WTIMO/RTIMO and NOTE_NOTIFY_ACK, which
 * come from XNU's own TCP and interface policy.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

#include "private.h"

/* XNU's socket event data (bsd/sys/socketvar.h, PRIVATE) */
#define SOCKEV_CONNECTED        0x00000001
#define SOCKEV_DISCONNECTED     0x00000002

/* The knote's state, as XNU keeps it in the knote */
struct sock_knote {
    uint32_t fflags;    /* XNU's kn_fflags: notes gathered since the last delivery (with EV_CLEAR) */
    uint32_t delivered; /* XNU's kn_hook32: level-triggered notes already delivered */
    unsigned state;     /* the socket's state when last looked at, to tell what changed */
    int error;          /* its pending error when last looked at */
    int efd;            /* wakes the knote outside the socket's events */
};

_Static_assert(sizeof(struct sock_knote) <= sizeof(((struct knote *) 0)->kn_extra_buffer),
        "struct sock_knote fits in a knote");

static struct sock_knote *
sock_knote(struct knote *kn)
{
    return (struct sock_knote *) &kn->kn_extra_buffer[0];
}

/* The hint XNU's TCP posts with this error: tcp_input()'s RST handling, tcp_timers()' drops */
static uint32_t
error_hint(int error)
{
    switch (error) {
    case ECONNREFUSED:
    case ECONNRESET:
        return NOTE_CONNRESET;
    case ETIMEDOUT:
    case EHOSTUNREACH:
    case ENETUNREACH:
    case EHOSTDOWN:
    case ENETDOWN:
        return NOTE_TIMEOUT;
    default:
        return 0;
    }
}

/*
 * filt_sockev_common(): whether the knote has something to report. hints: raise the one-shot notes from what
 * changed since the last look (attaching raises none: XNU's knote didn't see the hints posted before it). With out,
 * the knote is being delivered: fills it in and remembers what it delivered.
 */
static int
sock_evaluate(struct knote *kn, int hints, struct kevent64_s *out)
{
    struct sock_knote *sk = sock_knote(kn);
    unsigned state;
    int error;
    uint32_t level = 0;
    int64_t data;
    int ret = 0;

    if (_socket_state_4libkqueue(kn->kdata.kn_dupfd, &state, &error) < 0)
        return (0);

    if (hints) {
        if (error != 0 && error != sk->error)
            sk->fflags |= error_hint(error);
        if ((state & SOSTATE_EVCONNINFO) && (state & ~sk->state & (SOSTATE_ISCONNECTED | SOSTATE_ISDISCONNECTED)))
            sk->fflags |= NOTE_CONNINFO_UPDATED;
    }
    sk->state = state;
    sk->error = error;

    if (state & SOSTATE_ISCONNECTED) {
        sk->fflags |= NOTE_CONNECTED;
        level |= NOTE_CONNECTED;
    }
    if (state & SOSTATE_ISDISCONNECTED) {
        sk->fflags |= NOTE_DISCONNECTED;
        level |= NOTE_DISCONNECTED;
    }
    if (state & SOSTATE_CANTRCVMORE) {
        sk->fflags |= NOTE_READCLOSED;
        level |= NOTE_READCLOSED;
    }
    if (state & SOSTATE_CANTSENDMORE) {
        sk->fflags |= NOTE_WRITECLOSED;
        level |= NOTE_WRITECLOSED;
    }

    /* never suspended */
    sk->fflags &= ~(NOTE_SUSPEND | NOTE_RESUME);
    sk->delivered &= ~NOTE_SUSPEND;
    sk->fflags |= NOTE_RESUME;
    level |= NOTE_RESUME;

    if (error != 0) {
        ret = 1;
        data = error;
        kn->kev.flags |= EV_EOF;
    } else {
        data = (state & SOSTATE_ISCONNECTED) ? SOCKEV_CONNECTED : 0;
        data |= (state & SOSTATE_ISDISCONNECTED) ? SOCKEV_DISCONNECTED : 0;
    }

    /* only the notes asked for, and the level-triggered ones only until they're delivered */
    sk->fflags &= kn->kev.fflags & EVFILT_SOCK_ALL_MASK;
    level &= kn->kev.fflags & EVFILT_SOCK_ALL_MASK;
    level &= sk->delivered & EVFILT_SOCK_LEVEL_TRIGGER_MASK;
    if (sk->fflags & ~level)
        ret = 1;

    if (ret && out != NULL) {
        sk->delivered |= sk->fflags & EVFILT_SOCK_LEVEL_TRIGGER_MASK;
        if (sk->fflags & NOTE_SUSPEND)
            sk->delivered &= ~NOTE_RESUME;
        if (sk->fflags & NOTE_RESUME)
            sk->delivered &= ~NOTE_SUSPEND;

        kevent_int_to_64(&kn->kev, out);
        out->fflags = sk->fflags;
        out->data = data;
        if (kn->kev.flags & EV_CLEAR)
            sk->fflags = 0;
    }
    return (ret);
}

static void
sock_wake(struct knote *kn)
{
    uint64_t one = 1;

    (void) write(sock_knote(kn)->efd, &one, sizeof(one));
}

static int
sock_epoll(struct knote *kn, int op)
{
    struct epoll_event ev;

    /*
     * EPOLLOUT: a connect completing, and the shutdowns Linux reports no other way; RDHUP, HUP, ERR: the rest.
     * Edge-triggered, a socket that stays writable doesn't wake the knote again; data arriving never does.
     */
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLOUT | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET;
    ev.data.ptr = kn;
    if (epoll_ctl(kn->kn_epollfd, op, kn->kdata.kn_dupfd, &ev) < 0)
        return (-1);

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.ptr = kn;
    if (epoll_ctl(kn->kn_epollfd, op, sock_knote(kn)->efd, &ev) < 0) {
        if (op == EPOLL_CTL_ADD)
            (void) epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL);
        return (-1);
    }
    return (0);
}

static void
sock_unwatch(struct knote *kn)
{
    (void) epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, kn->kdata.kn_dupfd, NULL);
    (void) epoll_ctl(kn->kn_epollfd, EPOLL_CTL_DEL, sock_knote(kn)->efd, NULL);
}

int
evfilt_sock_copyout(struct kevent64_s *dst, struct knote *kn, void *ptr UNUSED)
{
    uint64_t count;

    /* whichever woke it */
    (void) read(sock_knote(kn)->efd, &count, sizeof(count));

    if (!sock_evaluate(kn, 1, dst)) {
        dst->filter = EVFILT_DROP;
        return (0);
    }

    /* XNU keeps a knote without EV_CLEAR (or EV_ONESHOT, EV_DISPATCH) active, and looks again next time */
    if (!(kn->kev.flags & (EV_CLEAR | EV_ONESHOT | EV_DISPATCH)))
        sock_wake(kn);
    return (0);
}

int
evfilt_sock_knote_create(struct filter *filt, struct knote *kn)
{
    struct sock_knote *sk = sock_knote(kn);
    unsigned state;
    int error;
    int ret;

    /* XNU's sokqfilter() takes EVFILT_SOCK on sockets; the other descriptors' kqfilters refuse it */
    ret = _socket_state_4libkqueue(kn->kev.ident, &state, &error);
    if (ret < 0)
        return (ret == -ENOTSOCK ? -EINVAL : ret);

    memset(sk, 0, sizeof(*sk));
    sk->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (sk->efd < 0)
        return (-1);
    kn->kdata.kn_dupfd = _dup_4libkqueue(kn->kev.ident);
    if (kn->kdata.kn_dupfd < 0) {
        (void) __close_for_kqueue(sk->efd);
        return (-1);
    }
    kn->kn_epollfd = filter_epfd(filt);

    /* filt_sockattach(): the knote is active at once if the socket's state has something to report */
    if (sock_evaluate(kn, 0, NULL))
        sock_wake(kn);

    if (sock_epoll(kn, EPOLL_CTL_ADD) < 0) {
        (void) __close_for_kqueue(kn->kdata.kn_dupfd);
        (void) __close_for_kqueue(sk->efd);
        return (-1);
    }
    return (0);
}

int
evfilt_sock_knote_modify(struct filter *filt UNUSED, struct knote *kn, const struct kevent64_s *kev)
{
    struct sock_knote *sk = sock_knote(kn);

    /* filt_socktouch(): forget delivering the level-triggered notes whose interest changed */
    uint32_t changed = kn->kev.fflags ^ sk->delivered;
    kn->kev.fflags = kev->fflags;
    kn->kev.data = kev->data;
    sk->delivered &= ~(changed & EVFILT_SOCK_LEVEL_TRIGGER_MASK);

    if (sock_evaluate(kn, 1, NULL))
        sock_wake(kn);
    return (0);
}

int
evfilt_sock_knote_delete(struct filter *filt UNUSED, struct knote *kn)
{
    if (!(kn->kev.flags & EV_DISABLE))
        sock_unwatch(kn);
    (void) __close_for_kqueue(kn->kdata.kn_dupfd);
    (void) __close_for_kqueue(sock_knote(kn)->efd);
    kn->kdata.kn_dupfd = -1;
    sock_knote(kn)->efd = -1;
    return (0);
}

int
evfilt_sock_knote_enable(struct filter *filt UNUSED, struct knote *kn)
{
    /* the readiness epoll finds when watching again wakes the knote if it has something to report */
    return (sock_epoll(kn, EPOLL_CTL_ADD));
}

int
evfilt_sock_knote_disable(struct filter *filt UNUSED, struct knote *kn)
{
    sock_unwatch(kn);
    return (0);
}

const struct filter evfilt_sock = {
    EVFILT_SOCK,
    NULL,
    NULL,
    evfilt_sock_copyout,
    evfilt_sock_knote_create,
    evfilt_sock_knote_modify,
    evfilt_sock_knote_delete,
    evfilt_sock_knote_enable,
    evfilt_sock_knote_disable,
};
