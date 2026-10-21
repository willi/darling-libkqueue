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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#include "private.h"

#ifdef DARLING
#include "../darling/listenregistry.h"
// the hooks libsystem_kernel calls (kqueue_close(), kqueue_closed_fd(), kqueue_dup(), kqueue_socket_changed())
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>
#endif

int DEBUG_KQUEUE = 0;
char *KQUEUE_DEBUG_IDENT = "KQ";

#ifdef _WIN32
static LONG kq_init_begin = 0;
static int kq_init_complete = 0;
#else
pthread_mutex_t kq_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_once_t kq_is_initialized = PTHREAD_ONCE_INIT;
#endif

static unsigned int
get_fd_limit(void)
{
#ifdef _WIN32
    /* actually windows should be able to hold
       way more, as they use HANDLEs for everything.
       Still this number should still be sufficient for
       the provided number of kqueue fds.
       */
    return 65536;
#else
    struct rlimit rlim;
    
    if (getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
        dbg_perror("getrlimit(2)");
        return (65536);
    } else {
        return (rlim.rlim_max);
    }
#endif
}

static struct map *kqmap;

// Every kqueue from kqueue_impl() until kqueue_free(), under kq_mtx. A kqueue stays on it while it has a reference
// (kqueue_delref() frees it, under kq_mtx, when the last one goes), so holding one keeps its place. kqueue_foreach()
// and kqueue_atfork() walk this list, not kqmap: kqmap has a slot for every descriptor RLIMIT_NOFILE's hard limit
// allows (1,048,576 in our containers), and walking all of them on every close() took most of a busy process's CPU.
//
// A kqueue is on the list whenever one of its descriptors maps to it in kqmap: it joins the list before its first
// slot is set and leaves after its last slot is cleared, and kq_dupfds is written before its slot. So a fork's child,
// which sees the parent's memory as it was at any of these steps, finds every slot it has to clear.
static LIST_HEAD(, kqueue) kq_list = LIST_HEAD_INITIALIZER(kq_list);

void
libkqueue_init(void)
{
#ifdef NDEBUG
    DEBUG_KQUEUE = 0;
#else
    char *s = getenv("KQUEUE_DEBUG");
    if (s != NULL && strlen(s) > 0) {
        DEBUG_KQUEUE = 1;

#ifdef _WIN32
    /* Initialize the Winsock library */
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2,2), &wsaData) != 0) 
        abort();
#endif

# if defined(_WIN32) && !defined(__GNUC__)
	/* Enable heap surveillance */
	{
		int tmpFlag = _CrtSetDbgFlag( _CRTDBG_REPORT_FLAG );
		tmpFlag |= _CRTDBG_CHECK_ALWAYS_DF;
		_CrtSetDbgFlag(tmpFlag);
	}
# endif /* _WIN32 */
    }
#endif

   kqmap = map_new(get_fd_limit()); // INT_MAX
   if (kqmap == NULL)
       abort(); 
   if (knote_init() < 0)
       abort();
   dbg_puts("library initialization complete");
#ifdef _WIN32
   kq_init_complete = 1;
#endif
}

#if DEADWOOD
static int
kqueue_cmp(struct kqueue *a, struct kqueue *b)
{
    return memcmp(&a->kq_id, &b->kq_id, sizeof(int)); 
}
#endif

void kqueue_cleanup(struct kqueue* kq)
{
    struct knote *next, *tmp;
    for (next = kq->kq_tofree.lh_first; next != NULL; next = tmp)
    {
        tmp = next->kn_entries2free.le_next;
        free(next);
    }
    LIST_INIT(&kq->kq_tofree);
}

/* Must hold kq_mtx when calling this */
void
kqueue_free(struct kqueue *kq)
{
	uint32_t i;

	kqueue_cleanup(kq);
	// Its descriptors leave kqmap: kq_id and kq_dupfds, the only ones that map to it, and then it leaves the list. A
	// slot another kqueue has taken since (kqueue_impl() replaces a stale one) stays as it is.
	map_remove(kqmap, kq->kq_id, kq);
	for (i = 0; i < kq->kq_ndupfds; i++)
		map_remove(kqmap, kq->kq_dupfds[i], kq);
	LIST_REMOVE(kq, kq_entry);
	free(kq->kq_dupfds);
    filter_unregister_all(kq);
    kqops.kqueue_free(kq);
    free(kq);
}

// The kqueue fd maps to in kqmap, kq_id after its close() included. Must hold kq_mtx.
static struct kqueue *
kqueue_lookup_slot(int fd)
{
    return ((struct kqueue *) map_lookup(kqmap, fd));
}

// The kqueue fd is a descriptor of: not kq_id once it has been closed (it stays open, and in kqmap, while other
// descriptors keep the kqueue; XNU's would fail with EBADF). Must hold kq_mtx.
struct kqueue *
kqueue_lookup(int fd)
{
    struct kqueue *kq = kqueue_lookup_slot(fd);

    if (kq != NULL && fd == kq->kq_id && kq->kq_id_closed)
        return (NULL);
    return (kq);
}

// Takes fd out of kq->kq_dupfds. Must hold kq_mtx. The last entry takes its place before the count goes down, so a
// fork's child reads every entry still in use.
static void
kqueue_dupfds_remove(struct kqueue *kq, int fd)
{
	uint32_t i;

	for (i = 0; i < kq->kq_ndupfds; i++) {
		if (kq->kq_dupfds[i] == fd) {
			kq->kq_dupfds[i] = kq->kq_dupfds[kq->kq_ndupfds - 1];
			atomic_dec(&kq->kq_ndupfds);
			return;
		}
	}
}

// fd, a descriptor kqueue_dup() added to kq, is no longer kq's: it leaves kqmap, kq_dupfds and its reference. Must
// hold kq_mtx.
static void
kqueue_drop_dup(struct kqueue *kq, int fd)
{
	map_remove(kqmap, fd, kq);
	kqueue_dupfds_remove(kq, fd);
	kqueue_delref(kq);
}

// close() of kqfd (libsystem_kernel's close.c). It returns 1 for kq_id: libkqueue closes the kqueue's own descriptor
// with the kqueue, once its last descriptor is closed. A descriptor kqueue_dup() added is dropped here, and gets 0, so
// that close() closes it.
int VISIBLE
kqueue_close(int kqfd)
{
	int result = 0;

    if (kqmap == NULL)
        return 0;

    pthread_mutex_lock(&kq_mtx);

    struct kqueue* kq = kqueue_lookup_slot(kqfd);
	if (kq != NULL && kqfd != kq->kq_id) {
		kqueue_drop_dup(kq, kqfd);
	} else if (kq != NULL) {
		result = 1;
		// kq_id stays open, and in kqmap, while other descriptors keep the kqueue. A second close() of it drops nothing.
		if (!kq->kq_id_closed) {
			kq->kq_id_closed = 1;
			kqueue_delref(kq);
		}
	}
    pthread_mutex_unlock(&kq_mtx);

	return result;
}

// Calls fn(kq, arg) for every live kqueue, each under its lock. kq_mtx is held only between kqueues, since fn may take
// other locks: the walk holds a reference on the kqueue it is at, which keeps that kqueue on the list, and takes one on
// the next before letting go of it. A kqueue created during the walk may be missed; one closed during it is visited if
// it still has a reference when the walk reaches it. Nothing is allocated, and each kqueue is visited once, however
// many descriptors map to it. The cost is one lock and three knote look-ups per kqueue: a process's kqueues include
// one per workloop (kevent_id.c).
//
// Neither kq_mtx nor the kqueue locks block signals, so a signal handler whose close(), connect() or shutdown() comes
// here can deadlock on a lock its own thread holds (as libsystem_kernel's sigsafe_lock.h tables can't).
static void
kqueue_foreach(void (*fn)(struct kqueue *, void *), void *arg)
{
	struct kqueue *kq, *next;

	pthread_mutex_lock(&kq_mtx);
	kq = LIST_FIRST(&kq_list);
	if (kq != NULL)
		kqueue_addref(kq);
	while (kq != NULL) {
		pthread_mutex_unlock(&kq_mtx);

		kqueue_lock(kq);
		fn(kq, arg);
		kqueue_unlock(kq);

		pthread_mutex_lock(&kq_mtx);
		next = LIST_NEXT(kq, kq_entry);
		if (next != NULL)
			kqueue_addref(next);
		kqueue_delref(kq);
		kq = next;
	}
	pthread_mutex_unlock(&kq_mtx);
}

static void
kqueue_closed_fd_cb(struct kqueue *kq, void *arg)
{
	struct kevent64_s *ev = arg;

	// we don't care whether these operations succeed or not
	kevent_copyin_one(kq, &ev[0]);
	kevent_copyin_one(kq, &ev[1]);
	kevent_copyin_one(kq, &ev[2]);
}

// Called on every close() of a descriptor that isn't kq_id (close.c), and for the descriptor dup2() replaces (dup2.c),
// so it costs one walk over the live kqueues (kqueue_foreach()), whatever RLIMIT_NOFILE is.
void VISIBLE
kqueue_closed_fd(int fd)
{
	if (kqmap == NULL)
		return;

	// close() succeeded, which leaves errno alone; the deletions below set it for each kqueue the fd isn't in
	int saved_errno = errno;
	struct kevent64_s ev[3];

	ev[0].ident = fd;
	ev[0].flags = EV_DELETE | EV_RECEIPT;
	ev[0].filter = EVFILT_READ;
	ev[1].ident = fd;
	ev[1].flags = EV_DELETE | EV_RECEIPT;
	ev[1].filter = EVFILT_WRITE;
	ev[2].ident = fd;
	ev[2].flags = EV_DELETE | EV_RECEIPT;
	ev[2].filter = EVFILT_SOCK;

	// it isn't a kqueue's kq_id (kqueue_close() keeps those), but it could be a fd inside a kqueue. Since we're
	// creating duplicates of all fd's, we now have to walk through all known kqueues and remove the fd from them.
	kqueue_foreach(kqueue_closed_fd_cb, ev);

#ifdef DARLING
    __darling_kqueue_unregister_listen(fd);
#endif

	errno = saved_errno;
}

static void
kqueue_socket_changed_cb(struct kqueue *kq, void *arg)
{
	struct filter *filt;
	struct knote *kn;

	if (filter_lookup(&filt, kq, EVFILT_SOCK) == 0) {
		kn = knote_lookup(filt, *(int *) arg);
		if (kn != NULL)
			evfilt_sock_changed(kn);
	}
}

// Darling's libsystem_kernel calls this after connect() and shutdown() on socket fd, while EVFILT_SOCK knotes exist
// (for-libkqueue.h): XNU's soevent() wakes the socket's EVFILT_SOCK knotes for those changes, and Linux wakes no one
// for some of them (a datagram socket connecting, a shutdown of only sending). The knote then looks at the socket
// again.
void VISIBLE
kqueue_socket_changed(int fd)
{
	if (kqmap == NULL)
		return;

	int saved_errno = errno;
	kqueue_foreach(kqueue_socket_changed_cb, &fd);
	errno = saved_errno;
}

// Adds fd to kq->kq_dupfds. Must hold kq_mtx. A full array is replaced by a bigger copy, and the old one is freed only
// once the new one is in place; the count goes up only once the entry is written. So a fork's child, whatever moment of
// this it sees, reads only entries that were written (kqueue_atfork()).
static int
kqueue_dupfds_add(struct kqueue *kq, int fd)
{
    if (kq->kq_ndupfds == kq->kq_dupfds_cap) {
        uint32_t cap = kq->kq_dupfds_cap ? kq->kq_dupfds_cap * 2 : 4;
        int *fds = malloc(cap * sizeof(*fds));
        int *old = kq->kq_dupfds;

        if (fds == NULL)
            return (-1);
        if (old != NULL)
            memcpy(fds, old, kq->kq_ndupfds * sizeof(*fds));
        kq->kq_dupfds = fds;
        kq->kq_dupfds_cap = cap;
        // the new array in place before the old one goes, for a fork's child on another CPU
#ifdef _WIN32
        MemoryBarrier();
#else
        __sync_synchronize();
#endif
        free(old);
    }
    kq->kq_dupfds[kq->kq_ndupfds] = fd;
    atomic_inc(&kq->kq_ndupfds);
    return (0);
}

// FIXME: this can race with someone closing the old FD right after it's dup'ed but before we're informed.
//        we should add a reference on the old FD before trying to dup it, then dup it, and then assign the reference
//        to the new FD if the dup succeeded or delete the reference if the dup failed.
void VISIBLE
kqueue_dup(int oldfd, int newfd)
{
    if (kqmap == NULL)
        return;

    pthread_mutex_lock(&kq_mtx);

    struct kqueue* kq = kqueue_lookup(oldfd);
    struct kqueue* cur = kqueue_lookup_slot(newfd);
    if (cur != NULL && cur != kq && newfd != cur->kq_id)
    {
        // dup2() replaced another kqueue's dup, or a dup of this one onto which a descriptor that isn't this kqueue's
        // was duplicated: dup2() closed it without telling libkqueue (dup2.c calls only kqueue_closed_fd())
        kqueue_drop_dup(cur, newfd);
        cur = NULL;
    }
    if (kq != NULL && cur == NULL)
    {
        // newfd maps to the kqueue, with a reference of its own, only once it is in kq_dupfds, for kqueue_free() and
        // kqueue_atfork()
        if (kqueue_dupfds_add(kq, newfd) < 0)
            dbg_puts("kqueue_dup: out of memory: the new descriptor is not the kqueue's");
        else if (map_insert(kqmap, newfd, kq) == 0)
            kqueue_addref(kq);
        else
            kqueue_dupfds_remove(kq, newfd);
    }
    else if (kq != NULL && cur == kq && newfd == kq->kq_id && kq->kq_id_closed && oldfd != newfd)
    {
        // dup2() of another of its descriptors onto kq_id after its close() (which left it open, kqueue_close()): it
        // is the kqueue's again
        kq->kq_id_closed = 0;
        kqueue_addref(kq);
    }
    // Otherwise newfd already maps to kq: dup2() of a descriptor onto itself or onto another of kq's, which dup2()
    // closed and replaced, so the reference stays. FIXME: or newfd is a kqueue's kq_id, and dup2() replaced that
    // kqueue's own epoll descriptor (which the kqueue still uses) with another file.

    pthread_mutex_unlock(&kq_mtx);

#ifdef DARLING
    if (__darling_kqueue_get_listen_status(oldfd))
        __darling_kqueue_register_listen(newfd);
#endif
}

// Closes fd in a fork's child if it maps to kq. A slot another kqueue has taken since is that kqueue's to close.
static void _kqueue_close_atfork(int fd, struct kqueue *kq)
{
    if (map_remove(kqmap, fd, kq) == 0)
        (void) __close_for_kqueue(fd);
}

void VISIBLE kqueue_atfork(void)
{
    struct kqueue *kq;
    uint32_t i;

    if (kqmap != NULL)
    {
        // Mutexes are not valid after a fork, reset it to unlocked state
        pthread_mutex_init(&kq_mtx, NULL);
        // A fork's child doesn't inherit kqueues: their descriptors are closed and leave kqmap. Every slot that maps to
        // a kqueue belongs to one on kq_list, in kq_id or kq_dupfds (see kq_list). Their objects are leaked rather than
        // freed: the child calls this before malloc is usable again (Darling's libsystem_kernel calls it from fork()
        // itself), so this must not allocate or free memory. The descriptors their knotes use are close-on-exec.
        LIST_FOREACH(kq, &kq_list, kq_entry)
        {
            _kqueue_close_atfork(kq->kq_id, kq);
            for (i = 0; i < kq->kq_ndupfds; i++)
                _kqueue_close_atfork(kq->kq_dupfds[i], kq);
        }
        LIST_INIT(&kq_list);
    }
}

void kqueue_addref(struct kqueue *kq)
{
	atomic_inc(&kq->kq_ref);
}

// Must hold kq_mtx: the last reference's kqueue_free() takes the kqueue off kq_list.
void kqueue_delref(struct kqueue *kq)
{
	if (!atomic_dec(&kq->kq_ref)) {
		kqueue_free(kq);
	}
}

int VISIBLE
kqueue_impl(void)
{
	struct kqueue *kq;
    struct kqueue *tmp;

#ifdef _WIN32
    if (InterlockedCompareExchange(&kq_init_begin, 0, 1) == 0) {
        libkqueue_init();
    } else {
        while (kq_init_complete == 0) {
            sleep(1);
        }
    }
#else
    (void) pthread_mutex_lock(&kq_mtx);
    (void) pthread_once(&kq_is_initialized, libkqueue_init);
    (void) pthread_mutex_unlock(&kq_mtx);
#endif

    kq = calloc(1, sizeof(*kq));
    if (kq == NULL)
        return (-1);

    kq->kq_ref = 1;
	tracing_mutex_init(&kq->kq_mtx, NULL);
    LIST_INIT(&kq->kq_tofree);

    if (kqops.kqueue_init(kq) < 0) {
        free(kq);
        return (-1);
    }

    dbg_printf("created kqueue, fd=%d", kq->kq_id);

    pthread_mutex_lock(&kq_mtx);
    tmp = map_delete(kqmap, kq->kq_id);
    if (tmp != NULL) {
        // The slot was stale: its kqueue stays allocated, and on kq_list, for good.
        dbg_puts("FIXME -- memory leak here");
        // TODO: kqops.kqueue_free(tmp), or (better yet) decrease it's refcount
    }
    // on kq_list before its slot is set (see kq_list)
    LIST_INSERT_HEAD(&kq_list, kq, kq_entry);
    if (map_insert(kqmap, kq->kq_id, kq) < 0) {
        LIST_REMOVE(kq, kq_entry);
        pthread_mutex_unlock(&kq_mtx);

        dbg_puts("map insertion failed");
        kqops.kqueue_free(kq);
        return (-1);
    }
    pthread_mutex_unlock(&kq_mtx);

    return (kq->kq_id);
}

static FILE* debug_file_actual_file = NULL;
static pthread_once_t debug_file_once_token = PTHREAD_ONCE_INIT;

static void init_debug_file(void) {
	if (getenv("KQUEUE_DEBUG_STDERR")) {
		debug_file_actual_file = stderr;
	} else {
		debug_file_actual_file = fopen("/tmp/kqueue-debug.log", "w");
	}
};

FILE* debug_file()
{
	pthread_once(&debug_file_once_token, init_debug_file);
	return debug_file_actual_file;
}
