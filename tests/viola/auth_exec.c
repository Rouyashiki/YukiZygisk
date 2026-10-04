/* SPDX-License-Identifier: Apache-2.0 */
/*
 * YukiZygisk - Kernel exec identity boundary fixtures.
 *
 * License: Apache-2.0
 *
 * Author: Anatdx
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "kernel/uapi/viola.h"
typedef uint32_t u32;
struct super_block { bool readonly; };
struct inode { unsigned int i_mode; struct super_block *i_sb; };
struct dentry { struct inode *inode; };
struct path { struct dentry *dentry; void *mnt; };
struct file { struct path f_path; };
struct fdtable { unsigned int max_fds; struct file **fd; };
struct files_struct { int file_lock; struct fdtable table; };
struct task_struct { struct files_struct *files; };
struct linux_binprm { struct file *file; bool have_execfd; int execfd; };
struct yz_auth_session { struct file *image; u32 role; int exec_seen; bool translated_exec; };
static struct task_struct task;
static struct task_struct *current = &task;
static struct path yz_auth_tango_path;
#define READ_ONCE(x) (x)
#define WRITE_ONCE(x, value) ((x) = (value))
#define file_inode(f) ((f)->f_path.dentry->inode)
#define d_inode(d) ((d)->inode)
#define sb_rdonly(sb) ((sb)->readonly)
#define files_fdtable(f) (&(f)->table)
#define rcu_dereference_raw(p) (p)
static void spin_lock(int *lock) { assert(!*lock); *lock = 1; }
static void spin_unlock(int *lock) { assert(*lock); *lock = 0; }
static int atomic_cmpxchg(int *p, int old, int next) {
  int prior = *p; if (prior == old) *p = next; return prior;
}
#include "viola_auth_functions.h"

int main(void) {
  struct super_block sb = {true};
  struct inode inodes[3] = {{S_IFREG, &sb}, {S_IFREG, &sb}, {S_IFREG, &sb}};
  struct dentry dentries[3] = {{&inodes[0]}, {&inodes[1]}, {&inodes[2]}};
  int mount, other_mount;
  struct file payload = {{&dentries[0], &mount}};
  struct file translator = {{&dentries[1], &mount}};
  struct file foreign = {{&dentries[2], &mount}};
  struct file reopened = payload;
  struct file *fds[4] = {NULL, NULL, NULL, &reopened};
  struct files_struct files = {0, {4, fds}};
  struct yz_auth_session session;
  struct linux_binprm bprm;
  unsigned int cases = 0;
#define RESET() do { \
  session = (struct yz_auth_session){&payload, YZ_VIOLA_ARMED32, 0, false}; \
  bprm = (struct linux_binprm){&translator, true, 3}; \
  task.files = &files; fds[3] = &reopened; sb.readonly = true; \
  translator.f_path.mnt = &mount; yz_auth_tango_path = translator.f_path; \
} while (0)
#define REJECT() do { assert(!yz_auth_record_exec(&session, &bprm)); \
  assert(!session.exec_seen && !session.translated_exec && !files.file_lock); ++cases; } while (0)
  RESET();
  assert(yz_auth_record_exec(&session, &bprm));
  assert(session.translated_exec && yz_auth_claim_image(&session, &translator));
  assert(!yz_auth_claim_image(&session, &payload));
  assert(!yz_auth_claim_image(&session, &foreign));
  assert(!yz_auth_record_exec(&session, &bprm)); /* one execution only */
  ++cases;
  for (unsigned role = YZ_VIOLA_QUERY; role <= YZ_VIOLA_DAEMON32; ++role) {
    if (role == YZ_VIOLA_ARMED32) continue;
    RESET(); session.role = role; REJECT();
  }
  RESET(); bprm.have_execfd = false; REJECT();
  RESET(); bprm.execfd = -1; REJECT();
  RESET(); bprm.execfd = 4; REJECT();
  RESET(); fds[3] = NULL; REJECT();
  RESET(); fds[3] = &foreign; REJECT();
  RESET(); task.files = NULL; REJECT();
  RESET(); yz_auth_tango_path.dentry = NULL; REJECT();
  RESET(); translator.f_path.mnt = &other_mount; REJECT();
  RESET(); bprm.file = &foreign; REJECT();
  RESET(); sb.readonly = false; REJECT();
  RESET(); session.image = NULL; REJECT();
  RESET(); bprm.file = NULL; REJECT();
  /* Native exec remains valid without binfmt evidence; file pointers may differ. */
  const u32 native_roles[] = {YZ_VIOLA_ARMED64, YZ_VIOLA_ARMED32, YZ_VIOLA_DELEGATED32};
  for (unsigned i = 0; i < sizeof(native_roles) / sizeof(native_roles[0]); ++i) {
    RESET(); session.role = native_roles[i]; bprm.file = &reopened; bprm.have_execfd = false;
    assert(yz_auth_record_exec(&session, &bprm));
    assert(!session.translated_exec && yz_auth_claim_image(&session, &reopened));
    assert(!yz_auth_claim_image(&session, &translator));
    ++cases;
  }
  RESET(); assert(!yz_auth_claim_image(&session, &translator));
  assert(yz_auth_record_exec(&session, &bprm));
  session.role = YZ_VIOLA_ARMED64;
  assert(!yz_auth_claim_image(&session, &translator)); ++cases;
  printf("%u kernel execution identity scenarios passed\n", cases);
  return 0;
}
