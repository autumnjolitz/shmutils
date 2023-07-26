import cffi
import platform

ffi = cffi.FFI()
ffi.cdef(
    """


extern "Python" void mmap_fork_callback(void);

typedef int... mode_t;

int
shm_open(const char *name, int oflag, mode_t mode);
int
shm_unlink(const char *name);

typedef int... off_t;

void *mmap(
     void *addr,
     size_t len,
     int prot,
     int flags,
     int fd,
     off_t offset
);
int munmap(void *addr, size_t len);

int mprotect(void *addr, size_t len, int prot);

int pthread_atfork(void (*prepare)(void), void (*parent)(void), void (*child)(void));

/* constants */
static const int MAP_FIXED;
static const int MAP_NORESERVE;

static const int PTHREAD_PROCESS_SHARED;
static const int PTHREAD_PROCESS_PRIVATE;


static const int PTHREAD_MUTEX_NORMAL;
static const int PTHREAD_MUTEX_ERRORCHECK;
static const int PTHREAD_MUTEX_RECURSIVE;
static const int PTHREAD_MUTEX_DEFAULT;


/* time related */
struct timespec { ...; };

/* Mutex */
typedef struct { ...; } pthread_mutex_t;
typedef struct { ...; } pthread_mutexattr_t;

int pthread_mutex_init(pthread_mutex_t *restrict mutex, const pthread_mutexattr_t *restrict attr);
int pthread_mutex_destroy(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);

int pthread_mutexattr_init(pthread_mutexattr_t *attr);
int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
int pthread_mutexattr_gettype(pthread_mutexattr_t *attr, int *type);

int pthread_mutexattr_getpshared(const pthread_mutexattr_t *restrict attr, int *restrict pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared);


/* Condition vars */
typedef struct { ...; } pthread_cond_t;
typedef struct { ...; } pthread_condattr_t;

int pthread_condattr_init(pthread_condattr_t *attr);
int pthread_condattr_destroy(pthread_condattr_t *attr);
int pthread_condattr_setpshared(pthread_condattr_t * attr, int pshared);
int pthread_condattr_getpshared(const pthread_condattr_t *restrict attr, int *restrict pshared);

int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
int pthread_cond_destroy(pthread_cond_t *cond);
int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime);
int pthread_cond_signal(pthread_cond_t *cond);
int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);
int pthread_cond_broadcast(pthread_cond_t *cond);

/* RW locks */
typedef struct { ...; } pthread_rwlock_t;
typedef struct { ...; } pthread_rwlockattr_t;

int pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_init(pthread_rwlockattr_t *attr);
int pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared);
int pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr, int *restrict pshared);

int pthread_rwlock_init(pthread_rwlock_t *restrict rwlock, const pthread_rwlockattr_t *restrict attr);
int pthread_rwlock_destroy(pthread_rwlock_t *rwlock);
int pthread_rwlock_unlock(pthread_rwlock_t *rwlock);

/* RW locks - read */
int pthread_rwlock_rdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_tryrdlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_timedrdlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abs_timeout);

/* RW locks - write */
int pthread_rwlock_timedwrlock(pthread_rwlock_t *restrict rwlock, const struct timespec *restrict abs_timeout);
int pthread_rwlock_trywrlock(pthread_rwlock_t *rwlock);
int pthread_rwlock_wrlock(pthread_rwlock_t *rwlock);


"""  # noqa
)
libraries = ["pthread"]
if platform.system().lower() in ("linux",):
    libraries.append("rt")

ffi.set_source(
    "shmutils._shmutils",
    r"""
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
    """,
    libraries=libraries,
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
