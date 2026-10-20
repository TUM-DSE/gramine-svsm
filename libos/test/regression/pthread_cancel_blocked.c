/* pthread_cancel() of a thread blocked in a restartable system call must act.
 *
 * glibc >= 2.41 acts on SIGCANCEL only if the interrupted PC lies inside its cancellable syscall
 * sequence, and SIGCANCEL is SA_RESTART: the LibOS's restart_syscall() must rewind the PC to the
 * caller's syscall instruction(s), as Linux does, or the cancel is dropped and the call blocks
 * again (read, recv, futex as in pthread_cond_wait). sleep() (EINTR, not restarted) is the control
 * that passes either way. With glibc <= 2.40 every case passes regardless.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <gnu/libc-version.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int g_pipe[2];
static int g_sock[2];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cond = PTHREAD_COND_INITIALIZER;

static void* reader(void* arg) {
    (void)arg;
    char c;
    read(g_pipe[0], &c, 1);
    return NULL;
}

static void* receiver(void* arg) {
    (void)arg;
    char c;
    recv(g_sock[0], &c, 1, 0);
    return NULL;
}

static void unlock(void* m) {
    pthread_mutex_unlock(m);
}

static void* cond_waiter(void* arg) {
    (void)arg;
    pthread_mutex_lock(&g_mutex);
    pthread_cleanup_push(unlock, &g_mutex);
    for (;;)
        pthread_cond_wait(&g_cond, &g_mutex);
    pthread_cleanup_pop(1);
    return NULL;
}

static void* sleeper(void* arg) {
    (void)arg;
    for (;;)
        sleep(100);
    return NULL;
}

static int run(const char* name, void* (*fn)(void*)) {
    pthread_t t;
    if (pthread_create(&t, NULL, fn, NULL) != 0) {
        printf("%s: pthread_create failed\n", name);
        return 0;
    }
    sleep(1); /* let it block */
    pthread_cancel(t);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 5;
    void* ret = NULL;
    int err = pthread_timedjoin_np(t, &ret, &deadline);
    if (err) {
        printf("%s: not cancelled (join: %s)\n", name, strerror(err));
        return 0;
    }
    if (ret != PTHREAD_CANCELED) {
        printf("%s: joined, but not cancelled\n", name);
        return 0;
    }
    printf("%s: cancelled\n", name);
    return 1;
}

int main(void) {
    setbuf(stdout, NULL);
    printf("glibc %s\n", gnu_get_libc_version());
    if (pipe(g_pipe) || socketpair(AF_UNIX, SOCK_STREAM, 0, g_sock)) {
        printf("setup failed: %s\n", strerror(errno));
        return 1;
    }
    int ok = run("read", reader) + run("recv", receiver) + run("cond_wait", cond_waiter)
             + run("sleep", sleeper);
    if (ok != 4) {
        printf("%d/4 cancelled\n", ok);
        return 1;
    }
    puts("TEST OK");
    /* The cancelled threads are gone; the blocked fds are never written. */
    return 0;
}
