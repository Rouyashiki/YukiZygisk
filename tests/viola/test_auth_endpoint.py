import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class EndpointAuthTests(unittest.TestCase):
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
