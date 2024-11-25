### 前提

本文参考[ubuntu16.04 fuzzing工具AFL安装使用以及问题解决](https://www.kanxue.com/chm.htm?id=16180&pid=node1001451)，复现学习。

### 安装

直接下载[afl源码](https://github.com/google/AFL)，之后make、sudo make install安装。

在文件`/proc/sys/kernel/core_pattern`中写入core。
```
$ sudo su
# echo core > /proc/sys/kernel/core_pattern
```

### 白盒测试

```bash
afl-gcc -g -o <target_file> <source_file>
afl-fuzz -i <input_dir> -o <output_dir> <target_file>
```

### 黑盒测试

需要对源码环境进行修改。
```bash
$ pwd
~/Projects/Fuzz/AFL
$ cd qemu_mode/
$ vim patches/syscall.diff
```
使用以下内容覆盖([参考](https://blog.csdn.net/geniusle201/article/details/111028697))。
```
--- qemu-2.10.0-clean/linux-user/syscall.c	2020-03-12 18:47:47.898592169 +0100
+++ qemu-2.10.0/linux-user/syscall.c	2020-03-12 19:16:41.563074307 +0100
@@ -34,6 +34,7 @@
 #include <sys/resource.h>
 #include <sys/swap.h>
 #include <linux/capability.h>
+#include <linux/sockios.h> // https://lkml.org/lkml/2019/6/3/988
 #include <sched.h>
 #include <sys/timex.h>
 #ifdef __ia64__
@@ -116,6 +117,8 @@ int __clone2(int (*fn)(void *), void *ch
 #include "qemu.h"

+extern unsigned int afl_forksrv_pid;
+
 #ifndef CLONE_IO
 #define CLONE_IO                0x80000000      /* Clone io context */
 #endif
 
@@ -256,7 +259,9 @@ static type name (type1 arg1,type2 arg2,
 #endif

 #ifdef __NR_gettid
-_syscall0(int, gettid)
+// taken from https://patchwork.kernel.org/patch/10862231/
+#define __NR_sys_gettid __NR_gettid
+_syscall0(int, sys_gettid)
 #else
 /* This is a replacement for the host gettid() and must return a host
    errno. */
@@ -6219,7 +6224,8 @@ static void *clone_func(void *arg)
     cpu = ENV_GET_CPU(env);
     thread_cpu = cpu;
     ts = (TaskState *)cpu->opaque;
-    info->tid = gettid();
+    // taken from https://patchwork.kernel.org/patch/10862231/
+    info->tid = sys_gettid();
     task_settid(ts);
     if (info->child_tidptr)
         put_user_u32(info->tid, info->child_tidptr);
@@ -6363,9 +6369,11 @@ static int do_fork(CPUArchState *env, un
                mapping.  We can't repeat the spinlock hack used above because
                the child process gets its own copy of the lock.  */
             if (flags & CLONE_CHILD_SETTID)
-                put_user_u32(gettid(), child_tidptr);
+                // taken from https://patchwork.kernel.org/patch/10862231/
+                put_user_u32(sys_gettid(), child_tidptr);
             if (flags & CLONE_PARENT_SETTID)
-                put_user_u32(gettid(), parent_tidptr);
+                // taken from https://patchwork.kernel.org/patch/10862231/
+                put_user_u32(sys_gettid(), parent_tidptr);
             ts = (TaskState *)cpu->opaque;
             if (flags & CLONE_SETTLS)
                 cpu_set_tls (env, newtls);
@@ -11402,7 +11410,8 @@ abi_long do_syscall(void *cpu_env, int n
         break;
 #endif
     case TARGET_NR_gettid:
-        ret = get_errno(gettid());
+        // taken from https://patchwork.kernel.org/patch/10862231/
+        ret = get_errno(sys_gettid());
         break;
 #ifdef TARGET_NR_readahead
     case TARGET_NR_readahead:
```

然后运行build_qemu_support.sh，如果显示缺少依赖就安装。
安装完毕之后。
```bash
$ cd ..
$ sudo make install
```
fuzz无源码的可执行文件。
```bash
$ gcc -g -o <target_file> <source_file>
$ afl-fuzz -Q -i <input_dir> -o <output_dir> <target_file>
```