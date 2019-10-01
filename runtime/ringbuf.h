/*
 * Copyright (c) 2016 Mindaugas Rasiukevicius <rmind at noxt eu>
 * All rights reserved.
 *
 * Use is subject to license terms, as specified in the LICENSE file.
 */

#ifndef _RINGBUF_H_
#define _RINGBUF_H_

#include "base/logging.h"

#define ASSERT(x) CHECK(x)

/*
 * Minimum, maximum and rounding macros.
 */

#ifndef MIN
#define MIN(x, y)   ((x) < (y) ? (x) : (y))
#endif

#ifndef MAX
#define MAX(x, y)   ((x) > (y) ? (x) : (y))
#endif

/*
 * Branch prediction macros.
 */
#ifndef __predict_true
#define __predict_true(x)   __builtin_expect((x) != 0, 1)
#define __predict_false(x)  __builtin_expect((x) != 0, 0)
#endif

/*
 * Atomic operations and memory barriers.  If C11 API is not available,
 * then wrap the GCC builtin routines.
 */
#ifndef atomic_compare_exchange_weak
#define atomic_compare_exchange_weak(ptr, expected, desired) \
  __sync_bool_compare_and_swap(ptr, expected, desired)
#endif

#ifndef atomic_thread_fence
#define memory_order_relaxed    __ATOMIC_RELAXED
#define memory_order_acquire    __ATOMIC_ACQUIRE
#define memory_order_release    __ATOMIC_RELEASE
#define memory_order_seq_cst    __ATOMIC_SEQ_CST
#define atomic_thread_fence(m)  __atomic_thread_fence(m)
#endif
#ifndef atomic_store_explicit
#define atomic_store_explicit   __atomic_store_n
#endif
#ifndef atomic_load_explicit
#define atomic_load_explicit    __atomic_load_n
#endif

/*
 * Exponential back-off for the spinning paths.
 */
#define SPINLOCK_BACKOFF_MIN    4
#define SPINLOCK_BACKOFF_MAX    128
#if defined(__x86_64__) || defined(__i386__)
#define SPINLOCK_BACKOFF_HOOK   __asm volatile("pause" ::: "memory")
#else
#define SPINLOCK_BACKOFF_HOOK
#endif
#define SPINLOCK_BACKOFF(count)                 \
do {                                \
  for (int __i = (count); __i != 0; __i--) {      \
    SPINLOCK_BACKOFF_HOOK;              \
  }                           \
  if ((count) < SPINLOCK_BACKOFF_MAX)         \
    (count) += (count);             \
} while (/* CONSTCOND */ 0);


namespace art {

typedef uint32_t        ringbuf_off_t;

typedef struct ringbuf_worker {
  volatile ringbuf_off_t  seen_off;
  int                     registered;
} ringbuf_worker_t;

typedef struct ringbuf {
  /* Ring buffer space. */
  size_t                  space;

  /*
   * The NEXT hand is atomically updated by the producer.
   * WRAP_LOCK_BIT is set in case of wrap-around; in such case,
   * the producer can update the 'end' offset.
   */
  volatile ringbuf_off_t  next;
  ringbuf_off_t           end;

  /* The following are updated by the consumer. */
  ringbuf_off_t           written;
  unsigned                nworkers;
  ringbuf_worker_t        workers[];
} ringbuf_t;

int             ringbuf_setup(ringbuf_t *, unsigned, size_t);
void            ringbuf_get_sizes(unsigned, size_t *, size_t *);

ringbuf_worker_t *ringbuf_register(ringbuf_t *, unsigned);
void            ringbuf_unregister(ringbuf_t *, ringbuf_worker_t *);

ssize_t         ringbuf_acquire(ringbuf_t *, ringbuf_worker_t *, size_t);
void            ringbuf_produce(ringbuf_t *, ringbuf_worker_t *);
size_t          ringbuf_consume(ringbuf_t *, size_t *);
void            ringbuf_release(ringbuf_t *, size_t);

size_t          ringbuf_w2i(ringbuf_t *, ringbuf_worker_t *);

}

#endif  // _RINGBUF_H_
