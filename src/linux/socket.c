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
 * - XNU's TCP's one-shot hints come from the state changes that raise them: libsystem_kernel counts the socket's
 *   resets (NOTE_CONNRESET) and timeouts (NOTE_TIMEOUT) while a knote watches it, also those the program took before
 *   the knote looked; connecting or disconnecting updates TCP's connection info (NOTE_CONNINFO_UPDATED);
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
    unsigned resets;    /* the socket's reset and timeout counts then (struct socket_state_4libkqueue) */
    unsigned timeouts;
    unsigned gen;       /* the kevent() copyout that last looked at it (KQUEUE_PLATFORM_SPECIFIC) */
    int efd;            /* wakes the knote outside the socket's events */
};

_Static_assert(sizeof(struct sock_knote) <= sizeof(((struct knote *) 0)->kn_extra_buffer),
        "struct sock_knote fits in a knote");

static struct sock_knote *
sock_knote(struct knote *kn)
{
    return (struct sock_knote *) &kn->kn_extra_buffer[0];
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
    struct socket_state_4libkqueue st;
    unsigned state;
    int error;
    uint32_t level = 0;
    int64_t data;
    int ret = 0;

    if (_socket_state_4libkqueue(kn->kdata.kn_dupfd, &st) < 0)
        return (0);
    state = st.state;
    error = st.error;

    /*
     * XNU's TCP posts these hints (other protocols post none); they're one-shot, so taken from what changed. The
     * counts only grow: one below the knote's is the socket's, forgotten and remembered again.
     */
    hints = hints && (state & SOSTATE_EVCONNINFO);
    if (st.resets > sk->resets) {
        if (hints)
            sk->fflags |= NOTE_CONNRESET;
        sk->resets = st.resets;
    }
    if (st.timeouts > sk->timeouts) {
        if (hints)
            sk->fflags |= NOTE_TIMEOUT;
        sk->timeouts = st.timeouts;
    }
    if (hints && (state & ~sk->state & (SOSTATE_ISCONNECTED | SOSTATE_ISDISCONNECTED)))
        sk->fflags |= NOTE_CONNINFO_UPDATED;
    sk->state = state;

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

void
evfilt_sock_changed(struct knote *kn)
{
    if (!(kn->kev.flags & EV_DISABLE))
        sock_wake(kn);
}

/* Watches fd in the knote's epoll set; one already watched counts (enabling an enabled knote, as XNU allows) */
static int
sock_watch_one(struct knote *kn, int fd, uint32_t events)
{
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.ptr = kn;
    if (epoll_ctl(kn->kn_epollfd, EPOLL_CTL_ADD, fd, &ev) < 0 && errno != EEXIST)
        return (-errno);
    return (0);
}

/*
 * EPOLLOUT: a connect completing, and the shutdowns Linux reports no other way; RDHUP, HUP, ERR: the rest.
 * Edge-triggered, a socket that stays writable doesn't wake the knote again; data arriving never does. Both entries
 * carry the knote, so one kevent() can return it twice: evfilt_sock_copyout() reports it once.
 */
static int
sock_watch(struct knote *kn)
{
    int ret = sock_watch_one(kn, kn->kdata.kn_dupfd, EPOLLOUT | EPOLLRDHUP | EPOLLHUP | EPOLLERR | EPOLLET);

    if (ret == 0)
        ret = sock_watch_one(kn, sock_knote(kn)->efd, EPOLLIN | EPOLLET);
    return (ret);
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
    struct sock_knote *sk = sock_knote(kn);
    uint64_t count;

    /* another thread's kevent() delivered it from its other epoll entry, and disabled it (EV_DISPATCH) */
    if (kn->kev.flags & EV_DISABLE) {
        dst->filter = EVFILT_DROP;
        return (0);
    }

    /* the knote's other epoll entry was ready too, in this same kevent(): it has been reported (or dropped) */
    if (sk->gen == kn->kn_kq->kq_copyout_gen) {
        dst->filter = EVFILT_DROP;
        return (0);
    }
    sk->gen = kn->kn_kq->kq_copyout_gen;

    /* whichever woke it */
    (void) read(sk->efd, &count, sizeof(count));

    if (!sock_evaluate(kn, 1, dst)) {
        dst->filter = EVFILT_DROP;
        return (0);
    }

    /* XNU keeps a knote without EV_CLEAR (or EV_ONESHOT, EV_DISPATCH) active, and looks again next time */
    if (!(kn->kev.flags & (EV_CLEAR | EV_ONESHOT | EV_DISPATCH)))
        sock_wake(kn);
    return (0);
}

/* Returns 0, or a negative errno (kn_create's convention, private.h) */
int
evfilt_sock_knote_create(struct filter *filt, struct knote *kn)
{
    struct sock_knote *sk = sock_knote(kn);
    struct socket_state_4libkqueue st;
    int ret;

    /* watched first: an error the program takes while the knote attaches is counted for it */
    _socket_watch_4libkqueue(kn->kev.ident, 1);

    /* XNU's sokqfilter() takes EVFILT_SOCK on sockets; the other descriptors' kqfilters refuse it */
    ret = _socket_state_4libkqueue(kn->kev.ident, &st);
    if (ret < 0) {
        _socket_watch_4libkqueue(kn->kev.ident, -1);
        return (ret == -ENOTSOCK ? -EINVAL : ret);
    }

    memset(sk, 0, sizeof(*sk));
    sk->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (sk->efd < 0) {
        ret = -errno;
        _socket_watch_4libkqueue(kn->kev.ident, -1);
        return (ret);
    }
    kn->kdata.kn_dupfd = _dup_4libkqueue(kn->kev.ident);
    if (kn->kdata.kn_dupfd < 0) {
        ret = kn->kdata.kn_dupfd;
        (void) __close_for_kqueue(sk->efd);
        _socket_watch_4libkqueue(kn->kev.ident, -1);
        return (ret);
    }
    kn->kn_epollfd = filter_epfd(filt);

    /* filt_sockattach(): the knote is active at once if the socket's state has something to report */
    if (sock_evaluate(kn, 0, NULL))
        sock_wake(kn);

    ret = sock_watch(kn);
    if (ret < 0) {
        sock_unwatch(kn);
        _socket_watch_4libkqueue(kn->kdata.kn_dupfd, -1);
        (void) __close_for_kqueue(kn->kdata.kn_dupfd);
        (void) __close_for_kqueue(sk->efd);
        return (ret);
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
    /* while the copy still names the socket */
    _socket_watch_4libkqueue(kn->kdata.kn_dupfd, -1);
    (void) __close_for_kqueue(kn->kdata.kn_dupfd);
    (void) __close_for_kqueue(sock_knote(kn)->efd);
    kn->kdata.kn_dupfd = -1;
    sock_knote(kn)->efd = -1;
    return (0);
}

int
evfilt_sock_knote_enable(struct filter *filt UNUSED, struct knote *kn)
{
    int ret = sock_watch(kn);

    /* not watched at all rather than by half: it stays disabled */
    if (ret < 0) {
        sock_unwatch(kn);
        kn->kev.flags |= EV_DISABLE;
        errno = -ret;
        return (-1);
    }
    /* XNU's knote_enable() looks at an enabled knote again: what it has to report doesn't wait for a new edge */
    if (sock_evaluate(kn, 1, NULL))
        sock_wake(kn);
    return (0);
}

int
evfilt_sock_knote_disable(struct filter *filt UNUSED, struct knote *kn)
{
    sock_unwatch(kn);
    return (0);
}

/*
 * The kqueue is being freed: its knotes go, as XNU's kqueue_close() drops a kqueue's knotes, so that their sockets'
 * watches stop and their copies of the sockets are closed
 */
static void
evfilt_sock_destroy(struct filter *filt)
{
    knote_delete_all(filt);
}

const struct filter evfilt_sock = {
    EVFILT_SOCK,
    NULL,
    evfilt_sock_destroy,
    evfilt_sock_copyout,
    evfilt_sock_knote_create,
    evfilt_sock_knote_modify,
    evfilt_sock_knote_delete,
    evfilt_sock_knote_enable,
    evfilt_sock_knote_disable,
};
