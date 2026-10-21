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

#ifndef  _KQUEUE_PRIVATE_H
#define  _KQUEUE_PRIVATE_H

#include <errno.h>
#include <stdio.h>
#include <string.h>
// #include "config.h"
#include "tree.h"
#include <sys/queue.h>

/* Maximum events returnable in a single kevent() call */
#define MAX_KEVENT  512

struct kqueue;
struct kevent64;
struct knote;
struct map;
struct eventfd;
struct evfilt_data;

#if defined(_WIN32)
# include "../windows/platform.h"
# include "../common/queue.h"
# if !defined(NDEBUG) && !defined(__GNUC__)
#  include <crtdbg.h>
# endif
#elif defined(__linux__)
# include "../posix/platform.h"
# include "../linux/platform.h"
#elif defined(__sun)
# include "../posix/platform.h"
# include "../solaris/platform.h"
#else
# error Unknown platform
#endif

#ifdef DARLING
typedef int timer_t;
int __close_for_kqueue(int fd);
#endif

#include "debug.h"

/* Workaround for Android */
#ifndef EPOLLONESHOT
# define EPOLLONESHOT (1 << 30)
#endif

struct eventfd {
    int ef_id;
#if defined(EVENTFD_PLATFORM_SPECIFIC)
    EVENTFD_PLATFORM_SPECIFIC;
#endif
};

/* 
 * Flags used by knote->kn_flags
 */
#define KNFL_PASSIVE_SOCKET  (0x01)  /* Socket is in listen(2) mode */
#define KNFL_REGULAR_FILE    (0x02)  /* File descriptor is a regular file */
#define KNFL_DEFER_DELETE    (0x04)  /* Defer deletion until re-enabled */
#define KNFL_KNOTE_DELETED   (0x10)  /* The knote object is no longer valid */

/*
 * XNU's private socket filter (bsd/sys/event.h, PRIVATE), which the SDK's headers leave out
 */
#ifndef EVFILT_SOCK
#define EVFILT_SOCK             (-13)
#define NOTE_CONNRESET          0x00000001
#define NOTE_READCLOSED         0x00000002
#define NOTE_WRITECLOSED        0x00000004
#define NOTE_TIMEOUT            0x00000008
#define NOTE_NOSRCADDR          0x00000010
#define NOTE_IFDENIED           0x00000020
#define NOTE_SUSPEND            0x00000040
#define NOTE_RESUME             0x00000080
#define NOTE_KEEPALIVE          0x00000100
#define NOTE_ADAPTIVE_WTIMO     0x00000200
#define NOTE_ADAPTIVE_RTIMO     0x00000400
#define NOTE_CONNECTED          0x00000800
#define NOTE_DISCONNECTED       0x00001000
#define NOTE_CONNINFO_UPDATED   0x00002000
#define NOTE_NOTIFY_ACK         0x00004000
#define EVFILT_SOCK_LEVEL_TRIGGER_MASK \
        (NOTE_READCLOSED | NOTE_WRITECLOSED | NOTE_SUSPEND | NOTE_RESUME | NOTE_CONNECTED | NOTE_DISCONNECTED)
#define EVFILT_SOCK_ALL_MASK \
        (NOTE_CONNRESET | NOTE_READCLOSED | NOTE_WRITECLOSED | NOTE_TIMEOUT | NOTE_NOSRCADDR | NOTE_IFDENIED | \
        NOTE_SUSPEND | NOTE_RESUME | NOTE_KEEPALIVE | NOTE_ADAPTIVE_WTIMO | NOTE_ADAPTIVE_RTIMO | NOTE_CONNECTED | \
        NOTE_DISCONNECTED | NOTE_CONNINFO_UPDATED | NOTE_NOTIFY_ACK)
#endif

#define EVFILT_DROP 0
#define EVFILT_DROP_POSTPROCESS (EVFILT_SYSCOUNT + 1)
 
struct knote {
    struct kevent_internal_s     kev;
    int               kn_flags;       
    union {
        /* OLD */
        int           pfd;       /* Used by timerfd */
        int           events;    /* Used by socket */
        struct {
            nlink_t   nlink;  /* Used by vnode */
            off_t     size;   /* Used by vnode */
        } vnode;
        timer_t       timerid;  
        struct sleepreq *sleepreq; /* Used by posix/timer.c */
		void          *handle;      /* Used by win32 filters */
    } data;
	struct kqueue*	   kn_kq;
    volatile uint32_t  kn_ref;
#if defined(KNOTE_PLATFORM_SPECIFIC)
    KNOTE_PLATFORM_SPECIFIC;
#endif
    RB_ENTRY(knote)   kn_entries;
    LIST_ENTRY(knote) kn_entries2free;
};

#define KNOTE_ENABLE(ent)           do {                            \
            (ent)->kev.flags &= ~EV_DISABLE;                        \
} while (0/*CONSTCOND*/)

#define KNOTE_DISABLE(ent)          do {                            \
            (ent)->kev.flags |=  EV_DISABLE;                        \
} while (0/*CONSTCOND*/)

struct filter {
    short     kf_id;

    /* filter operations */

    int     (*kf_init)(struct filter *);
    void    (*kf_destroy)(struct filter *);
    int     (*kf_copyout)(struct kevent64_s *, struct knote *, void *);

    /* knote operations */

    /*
     * Returns 0, or a negative errno for kevent() to fail the registration with. -1 means EBADF (as when filters
     * returned -1 on any failure), so a filter can't name EPERM.
     */
    int     (*kn_create)(struct filter *, struct knote *);
    int     (*kn_modify)(struct filter *, struct knote *, 
                            const struct kevent64_s *);
    int     (*kn_delete)(struct filter *, struct knote *);
    int     (*kn_enable)(struct filter *, struct knote *);
    int     (*kn_disable)(struct filter *, struct knote *);

    struct eventfd kf_efd;             /* Used by user.c */

    //MOVE TO POSIX?
    int       kf_pfd;                   /* fd to poll(2) for readiness */
    int       kf_wfd;                   /* fd to write when an event occurs */
    //----?

    struct evfilt_data *kf_data;	    /* filter-specific data */
    RB_HEAD(knt, knote) kf_knote;
    pthread_rwlock_t    kf_knote_mtx;
    struct kqueue      *kf_kqueue;
#if defined(FILTER_PLATFORM_SPECIFIC)
    FILTER_PLATFORM_SPECIFIC;
#endif
};

/* Use this to declare a filter that is not implemented */
#define EVFILT_NOTIMPL { 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }

struct kqueue {
    int             kq_id;
    struct filter   kq_filt[EVFILT_SYSCOUNT];
    fd_set          kq_fds, kq_rfds; 
    int             kq_nfds;
    tracing_mutex_t kq_mtx;
    volatile uint32_t kq_ref;
#if defined(KQUEUE_PLATFORM_SPECIFIC)
    KQUEUE_PLATFORM_SPECIFIC;
#endif
    RB_ENTRY(kqueue) entries;
    LIST_HEAD(knt2free, knote) kq_tofree;
    /* On kqueue.c's kq_list from kqueue_impl() until kqueue_free(), under the global kq_mtx */
    LIST_ENTRY(kqueue) kq_entry;
    /*
     * Under the global kq_mtx. The descriptors that map to this kqueue in kqmap besides kq_id: kqueue_dup() adds them,
     * and closing one takes it out (kqueue_close()). kq_ndupfds goes up only once its entry is written, and the array
     * is replaced, never moved, so a fork's child reads only written entries (kqueue_atfork()).
     */
    int             *kq_dupfds;
    volatile uint32_t kq_ndupfds;
    uint32_t        kq_dupfds_cap;
    /* kq_id was closed while other descriptors kept the kqueue (kqueue_close()), under the global kq_mtx */
    int             kq_id_closed;
};

struct kqueue_vtable {
    int  (*kqueue_init)(struct kqueue *);
    void (*kqueue_free)(struct kqueue *);
    // @param timespec can be given as timeout
    // @param int the number of events to wait for
    // @param kqueue the queue to wait on
	int  (*kevent_wait)(struct kqueue *, int, const struct timespec *);
    // @param kqueue the queue to look at
    // @param int The number of events that should be ready
    // @param kevent the structure to copy the events into
    // @param int The number of events to copy
    // @return the actual number of events copied
    int  (*kevent_copyout)(struct kqueue *, int, struct kevent64_s *, int);
    int  (*filter_init)(struct kqueue *, struct filter *);
    void (*filter_free)(struct kqueue *, struct filter *);
    int  (*eventfd_init)(struct eventfd *);
    void (*eventfd_close)(struct eventfd *);
    int  (*eventfd_raise)(struct eventfd *);
    int  (*eventfd_lower)(struct eventfd *);
    int  (*eventfd_descriptor)(struct eventfd *);
};
extern const struct kqueue_vtable kqops;

/*
 * kqueue internal API
 */
#define kqueue_lock(kq)     tracing_mutex_lock(&(kq)->kq_mtx)
#define kqueue_unlock(kq)   tracing_mutex_unlock(&(kq)->kq_mtx)

int kevent_copyin_one(struct kqueue *kq, const struct kevent64_s *src);

/*
 * knote internal API
 */
struct knote * knote_lookup(struct filter *, uintptr_t);

/* EVFILT_SOCK (src/linux/socket.c): wakes a knote to look at its socket again */
void evfilt_sock_changed(struct knote *);
//DEADWOOD: struct knote * knote_get_by_data(struct filter *filt, intptr_t);
struct knote * knote_new(void);
#define knote_retain(kn) atomic_inc(&kn->kn_ref)
void knote_release(struct knote *);
void knote_insert(struct filter *, struct knote *);
int  knote_delete(struct filter *, struct knote *);
/* Deletes every knote of the filter, whose kqueue is being freed */
void knote_delete_all(struct filter *);
int  knote_init(void);
int  knote_disable(struct filter *, struct knote *);
#define knote_get_filter(knt) &((knt)->kn_kq->kq_filt[(knt)->kev.filter])

int         filter_lookup(struct filter **, struct kqueue *, short);
int      	filter_register_all(struct kqueue *);
void     	filter_unregister_all(struct kqueue *);
const char *filter_name(short);

int         kevent_wait(struct kqueue *, const struct timespec *);
int         kevent_copyout(struct kqueue *, int, struct kevent64_s *, int);
void 		kevent_free(struct kqueue *);
const char *kevent_dump(const struct kevent64_s *);
struct kqueue * kqueue_lookup(int);
int         kqueue_validate(struct kqueue *);
void        kqueue_addref(struct kqueue *);
void        kqueue_delref(struct kqueue *);
// execute pending free() operations
void kqueue_cleanup(struct kqueue* kq);

struct map *map_new(size_t);
int         map_insert(struct map *, int, void *);
int         map_remove(struct map *, int, void *);
int         map_replace(struct map *, int, void *, void *);
void       *map_lookup(struct map *, int);
void       *map_delete(struct map *, int);
void        map_free(struct map *);

void kevent_64_to_int(const struct kevent64_s* e64, struct kevent_internal_s* eint);
void kevent_int_to_64(const struct kevent_internal_s* eint, struct kevent64_s* e64);

/* DEADWOOD: No longer needed due to the un-smerging of POSIX and Linux

int  posix_evfilt_user_init(struct filter *);
void posix_evfilt_user_destroy(struct filter *);
int  posix_evfilt_user_copyout(struct kevent64_s *, struct knote *, void *ptr UNUSED);
int  posix_evfilt_user_knote_create(struct filter *, struct knote *);
int  posix_evfilt_user_knote_modify(struct filter *, struct knote *, const struct kevent64_s *);
int  posix_evfilt_user_knote_delete(struct filter *, struct knote *);
int  posix_evfilt_user_knote_enable(struct filter *, struct knote *);
int  posix_evfilt_user_knote_disable(struct filter *, struct knote *);

*/

#endif  /* ! _KQUEUE_PRIVATE_H */
