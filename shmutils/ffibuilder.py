import cffi
import platform

ffi = cffi.FFI()
ffi.cdef(
    """
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

static const int MAP_FIXED;

typedef struct { ...; } pthread_mutex_t;
typedef struct { ...; } pthread_mutexattr_t;

typedef struct {
    char header[14];
    uint32_t size;
    uint32_t owner_pid;
} shmmmap_header_t;

int get_pthread_recursive_type(void);
int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_trylock(pthread_mutex_t *mutex);
int pthread_mutex_unlock(pthread_mutex_t *mutex);

int pthread_mutex_destroy(pthread_mutex_t *mutex);
 int
 pthread_mutexattr_init(pthread_mutexattr_t *attr);

 int
 pthread_mutexattr_destroy(pthread_mutexattr_t *attr);

 int
 pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling);

 int
 pthread_mutexattr_getprioceiling(pthread_mutexattr_t *attr, int *prioceiling);

 int
 pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol);

 int
 pthread_mutexattr_getprotocol(pthread_mutexattr_t *attr, int *protocol);

 int
 pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);

 int
 pthread_mutexattr_gettype(pthread_mutexattr_t *attr, int *type);

int pthread_mutex_init(pthread_mutex_t *restrict mutex, const pthread_mutexattr_t *restrict attr);
int pthread_mutexattr_getpshared(const pthread_mutexattr_t *
       restrict attr, int *restrict pshared);
int pthread_mutexattr_setpshared(pthread_mutexattr_t *attr,
       int pshared);
int get_pthread_process_shared(void);
"""
)
libraries = ["pthread"]
if platform.system().lower() in ("linux",):
    libraries.append("rt")

ffi.set_source(
    "_shmutils",
    r"""
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>

typedef struct {
    char header[14];
    uint32_t size;
    uint32_t owner_pid;
} shmmmap_header_t;

int get_pthread_process_shared(void){
    return PTHREAD_PROCESS_SHARED;
};
int get_pthread_recursive_type(void) {
    return PTHREAD_MUTEX_RECURSIVE;
};
    """,
    libraries=libraries,
)

if __name__ == "__main__":
    ffi.compile(verbose=True)
