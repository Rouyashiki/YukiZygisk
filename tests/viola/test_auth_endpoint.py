import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class EndpointAuthTests(unittest.TestCase):
    def test_endpoint_query_returns_while_kernel_locks_are_busy(self):
        root = Path(__file__).resolve().parents[2]
        auth = (root / 'kernel/core/auth.c').read_text()
        begin = auth.index('static bool yz_auth_query_request(')
        auth = auth[begin:auth.index('\nbool yz_auth_endpoint_abi(', begin)]
        control = (root / 'kernel/core/control.c').read_text()
        begin = control.index('static long yukizygisk_ioctl(struct file *file,')
        control = control[begin:control.index('\nstatic int yukizygisk_release(', begin)]
        fixture = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "kernel/uapi/yukizygisk.h"
#include "kernel/uapi/viola.h"
#include "kernel/uapi/viola_health.h"

#define __user
struct yz_auth_session { unsigned role; bool owns_current_image; };
struct file { struct yz_auth_session *private_data; };
static pthread_mutex_t yz_auth_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_rwlock_t yz_control_sem = PTHREAD_RWLOCK_INITIALIZER;
static bool yz_auth_enabled = true;
static int yz_control_available = 1;
static unsigned dispatched;
#define mutex_trylock(lock) (pthread_mutex_trylock(lock) == 0)
#define mutex_lock(lock) assert(pthread_mutex_lock(lock) == 0)
#define mutex_unlock(lock) assert(pthread_mutex_unlock(lock) == 0)
#define down_read_trylock(lock) (pthread_rwlock_tryrdlock(lock) == 0)
#define down_read(lock) assert(pthread_rwlock_rdlock(lock) == 0)
#define up_read(lock) assert(pthread_rwlock_unlock(lock) == 0)
#define atomic_read(value) (*(value))
static bool yz_auth_is_owner(struct yz_auth_session *session, bool check_mm) {
    assert(check_mm);
    return session->owns_current_image;
}
static long yz_auth_ioctl(struct yz_auth_session *session, unsigned request, void *arg) {
    (void)session;
    (void)request;
    (void)arg;
    return -ENOTTY;
}
static long yukizygisk_ioctl_dispatch(struct file *file, unsigned request, unsigned long arg) {
    assert(file->private_data && request == YZ_IOCTL_GET_ENDPOINT_STATE_FD && !arg);
    ++dispatched;
    return 0;
}
''' + auth + control + r'''
static pthread_barrier_t acquired, release_lock;
static void *hold_lock(void *opaque) {
    const bool control = *(const bool *)opaque;
    if (control)
        assert(pthread_rwlock_wrlock(&yz_control_sem) == 0);
    else
        mutex_lock(&yz_auth_lock);
    pthread_barrier_wait(&acquired);
    pthread_barrier_wait(&release_lock);
    if (control)
        up_read(&yz_control_sem);
    else
        mutex_unlock(&yz_auth_lock);
    return NULL;
}
int main(void) {
    struct yz_auth_session session = {YZ_VIOLA_ADMIN, true};
    struct file file = {&session};
    assert(pthread_barrier_init(&acquired, NULL, 2) == 0);
    assert(pthread_barrier_init(&release_lock, NULL, 2) == 0);
    for (unsigned i = 0; i < 2; ++i) {
        bool control = i == 0;
        pthread_t holder;
        assert(pthread_create(&holder, NULL, hold_lock, &control) == 0);
        pthread_barrier_wait(&acquired);
        assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == -EAGAIN);
        assert(dispatched == i);
        pthread_barrier_wait(&release_lock);
        assert(pthread_join(holder, NULL) == 0);
        assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == 0);
        assert(dispatched == i + 1);
    }
    session.owns_current_image = false;
    assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == -EPERM);
    session.owns_current_image = true;
    yz_auth_enabled = false;
    assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == -EPERM);
    yz_auth_enabled = true;
    yz_control_available = 0;
    assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == -ENODEV);
    yz_control_available = 1;
    assert(dispatched == 2);
    assert(yukizygisk_ioctl(&file, YZ_IOCTL_GET_ENDPOINT_STATE_FD, 0) == 0);
    assert(dispatched == 3);
    assert(pthread_barrier_destroy(&acquired) == 0);
    assert(pthread_barrier_destroy(&release_lock) == 0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='viola-endpoint-locks-') as temporary:
            directory = Path(temporary)
            source = directory / 'endpoint-locks.c'
            source.write_text(fixture)
            binary = directory / 'endpoint-locks'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2',
                            '-Wall', '-Wextra', '-Werror', '-pthread', '-I' + str(root),
                            str(source), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=5)

    def test_health_reports_busy_and_unsupported_endpoint_queries(self):
        root = Path(__file__).resolve().parents[2]
        fixture = r'''
#include <cassert>
#include <cerrno>
#include <cstdarg>
#include "kernel/uapi/yukizygisk.h"
#include "userspace/viola/recovery.h"

static int query_error;
static unsigned queries;
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
    assert(fd == 123 && request == YZ_IOCTL_GET_ENDPOINT_STATE_FD);
    va_list args;
    va_start(args, request);
    const auto *command = va_arg(args, yz_endpoint_fd_cmd *);
    va_end(args);
    assert(command->version == YZ_ENDPOINT_VERSION && command->fd == -1);
    assert(command->abi == ++queries && command->reserved == 0);
    errno = query_error;
    return -1;
}
int main() {
    const struct { int error; viola_health_state state; } cases[] = {
        {EAGAIN, VIOLA_HEALTH_UNRESPONSIVE},
        {ENOTTY, VIOLA_HEALTH_UNSUPPORTED},
        {EOPNOTSUPP, VIOLA_HEALTH_UNSUPPORTED},
        {EPROTONOSUPPORT, VIOLA_HEALTH_UNSUPPORTED},
        {EPERM, VIOLA_HEALTH_ERROR},
    };
    for (const auto &test : cases) {
        queries = 0;
        query_error = test.error;
        viola_health replies[2]{};
        viola_daemon_health(123, 10, replies);
        assert(queries == 2);
        for (const auto &reply : replies) {
            assert(reply.state == test.state && reply.error == test.error);
            assert(!reply.ready && !reply.pid);
        }
    }
}
'''
        with tempfile.TemporaryDirectory(prefix='viola-endpoint-health-') as temporary:
            directory = Path(temporary)
            source = directory / 'endpoint-health.cpp'
            source.write_text(fixture)
            binary = directory / 'endpoint-health'
            subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17', '-O2',
                            '-Wall', '-Wextra', '-Werror', '-I' + str(root),
                            str(source), str(root / 'userspace/viola/recovery.cpp'),
                            str(root / 'userspace/zygisk/endpoint.cpp'),
                            '-Wl,--wrap=ioctl', '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=5)

    def test_registered_daemon_abi_and_process_identity(self):
        root = Path(__file__).resolve().parents[2]
        source = (root / 'kernel/core/auth.c').read_text()
        begin = source.index('bool yz_auth_endpoint_abi(')
        end = source.index('\nint yz_auth_current_ticket', begin)
        fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include "kernel/uapi/yukizygisk.h"
#include "kernel/uapi/viola.h"
typedef uint32_t u32;
struct yz_auth_session { u32 role; bool owns_current_image; struct yz_auth_session *next; };
static struct yz_auth_session *yz_auth_sessions;
#define lockdep_assert_held(lock) ((void)0)
#define list_for_each_entry(item, head, member) for (item = *(head); item; item = item->next)
static bool yz_auth_is_owner(struct yz_auth_session *session, bool require_claim) {
    assert(require_claim);
    return session->owns_current_image;
}
''' + source[begin:end] + r'''
int main(void) {
    struct yz_auth_session wrong_process = {YZ_VIOLA_DAEMON64, false, 0};
    struct yz_auth_session daemon32 = {YZ_VIOLA_DAEMON32, true, &wrong_process};
    struct yz_auth_session control = {YZ_VIOLA_ADMIN, true, &daemon32};
    yz_auth_sessions = &control;
    assert(yz_auth_endpoint_abi(YZ_RUNTIME_ABI_32));
    assert(!yz_auth_endpoint_abi(YZ_RUNTIME_ABI_64));
    assert(!yz_auth_endpoint_abi(0));
    assert(!yz_auth_endpoint_abi(3));
    daemon32.owns_current_image = false;
    assert(!yz_auth_endpoint_abi(YZ_RUNTIME_ABI_32));
    wrong_process.owns_current_image = true;
    assert(yz_auth_endpoint_abi(YZ_RUNTIME_ABI_64));
    yz_auth_sessions = 0;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix='viola-endpoint-') as temporary:
            directory = Path(temporary)
            path = directory / 'endpoint.c'
            path.write_text(fixture)
            binary = directory / 'endpoint'
            subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2',
                            '-Wall', '-Wextra', '-Werror', '-I' + str(root),
                            str(path), '-o', str(binary)], check=True)
            subprocess.run([str(binary)], check=True, timeout=5)


if __name__ == '__main__':
    unittest.main()
