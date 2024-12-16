# 调试内核

## Kernel GDB scripts[1]

* `CONFIG_GDB_SCRIPTS`可以通过构建python脚本来简化内核调试(添加新命令和函数)
* 当使用gdb vmlinux时，会自动加载构建根目录中的vmlinux-gdb.py文件
  * lx-symbols: 为vmlinux和模块重载符号
  * lx-dmesg: 显示内核 dmesg
  * lx-lsmod:显示加载的模块
  * lx-device-{bus|class|tree}: 显示设备总线、类和树
  * lx-ps: ps 类似查看任务
  * $lx_current() 包含当前task_struct
  * $lx_per_cpu(var, cpu) 返回一个单-cpu变量
  * apropos lx 显示所有可用的函数

# 进程和线程

进程是操作系统的抽象概念，用于组织多个资源：
* 地址空间
* 一个或多个线程
* 打开的文件
* 套接字（Socket）
* 信号量（semaphore）
* 共享内存区域
* 定时器
* 信号处理程序
* 许多其他资源和状态信息

所有这些信息都被组织在进程控制块（PCB）中。在 Linux 中，PCB 对应的结构体是`struct task_struct`。

## 进程资源查询

我们可以在 /proc/\<pid\> 目录中获取关于进程资源的摘要信息，其中 \<pid\> 是我们要查看的进程的进程 ID。

```
                +-------------------------------------------------------------------+
                | dr-x------    2 tavi tavi 0  2021 03 14 12:34 .                   |
                | dr-xr-xr-x    6 tavi tavi 0  2021 03 14 12:34 ..                  |
                | lrwx------    1 tavi tavi 64 2021 03 14 12:34 0 -> /dev/pts/4     |
           +--->| lrwx------    1 tavi tavi 64 2021 03 14 12:34 1 -> /dev/pts/4     |
           |    | lrwx------    1 tavi tavi 64 2021 03 14 12:34 2 -> /dev/pts/4     |
           |    | lr-x------    1 tavi tavi 64 2021 03 14 12:34 3 -> /proc/18312/fd |
           |    +-------------------------------------------------------------------+
           |                 +----------------------------------------------------------------+
           |                 | 08048000-0804c000 r-xp 00000000 08:02 16875609 /bin/cat        |
$ ls -1 /proc/self/          | 0804c000-0804d000 rw-p 00003000 08:02 16875609 /bin/cat        |
cmdline    |                 | 0804d000-0806e000 rw-p 0804d000 00:00 0 [heap]                 |
cwd        |                 | ...                                                            |
environ    |    +----------->| b7f46000-b7f49000 rw-p b7f46000 00:00 0                        |
exe        |    |            | b7f59000-b7f5b000 rw-p b7f59000 00:00 0                        |
fd --------+    |            | b7f5b000-b7f77000 r-xp 00000000 08:02 11601524 /lib/ld-2.7.so  |
fdinfo          |            | b7f77000-b7f79000 rw-p 0001b000 08:02 11601524 /lib/ld-2.7.so  |
maps -----------+            | bfa05000-bfa1a000 rw-p bffeb000 00:00 0 [stack]                |
mem                          | ffffe000-fffff000 r-xp 00000000 00:00 0 [vdso]                 |
root                         +----------------------------------------------------------------+
stat                 +----------------------------+
statm                |  Name: cat                 |
status ------+       |  State: R (running)        |
task         |       |  Tgid: 18205               |
wchan        +------>|  Pid: 18205                |
                     |  PPid: 18133               |
                     |  Uid: 1000 1000 1000 1000  |
                     |  Gid: 1000 1000 1000 1000  |
                     +----------------------------+
```

## 线程

线程是内核进程调度器调度的基本单位，决定了应用程序在 CPU 上的运行。其主要特点如下：  
- **独立堆栈**：每个线程都有自己的堆栈，与寄存器的值共同决定了线程的运行状态。  
- **共享资源**：线程在进程的上下文中运行，同一进程中的所有线程共享资源。  
- **调度单位**：内核调度的是线程，而非进程。用户级线程（如纤程或协程）在内核级别不可见。  

线程的典型实现通常将线程作为独立的数据结构，并链接到进程数据结构。然而，Linux 采用了不同的方式，其基本调度单位称为“任务”（task），对应结构体 `struct task_struct`。这个结构既可以表示线程，也可以表示进程。资源不直接嵌入到任务结构中，而是通过指针指向相关资源，从而实现灵活的资源管理。

## 克隆

Linux 使用 `clone()` 系统调用来创建线程或进程，允许调用者通过标志位灵活选择资源共享或隔离的方式。以下是常见的标志选项：  
- **CLONE_FILES**：与父进程共享文件描述符表。  
- **CLONE_VM**：与父进程共享地址空间。  
- **CLONE_FS**：与父进程共享文件系统信息（如根目录和当前目录）。  
- **CLONE_NEWNS**：创建独立的挂载命名空间。  
- **CLONE_NEWIPC**：创建独立的 IPC 命名空间（如 System V IPC 对象或 POSIX 消息队列）。  
- **CLONE_NEWNET**：创建独立的网络命名空间（如网络接口或路由表）。  

调用 `clone()` 时：  
- 使用标志 `CLONE_FILES | CLONE_VM | CLONE_FS` 会创建一个新的线程，与父进程共享大部分资源。  
- 不使用这些标志则会创建一个新的进程，资源相对独立。  

## 命名空间与容器

容器是一种轻量级的虚拟化技术，与传统虚拟化方式不同。传统虚拟化依赖虚拟机监视程序（hypervisor），为每个虚拟机提供独立的内核实例。而容器技术共享相同的内核实例，提供更高的性能和资源利用率。  
常见的容器技术包括：  
- **LXC**：支持运行轻量级的“虚拟机”。  
- **Docker**：专注于运行单个应用程序的容器。  

容器的实现依赖于内核特性，其中最关键的就是 **命名空间（namespace）**。命名空间允许对资源进行隔离，防止全局资源的互相干扰。例如，在没有容器的情况下，所有进程在 `/proc` 中可见并可被操作，而容器可以隔离这些进程，使得一个容器中的进程对其他容器不可见。  

命名空间的实现通过内核中的 `struct nsproxy` 结构完成，支持对以下资源类型进行分区：  
- IPC  
- 网络  
- cgroup  
- 挂载点  
- PID  
- 时间命名空间  

例如，网络接口的默认状态是在全局范围内共享。然而，通过创建一个新的网络命名空间（如 `struct net`），系统可以隔离接口列表，新创建的进程指向新命名空间，从而实现资源隔离。

## 访问当前进程

访问当前进程信息是内核中的高频操作，以下是一些常见的场景：  
- 打开文件时需要访问 `struct task_struct` 的 `file` 字段。  
- 映射新文件时需要访问 `mm` 字段。  
- 超过 90% 的系统调用涉及当前进程的结构体操作，因此需要快速的访问路径。  

Linux 提供了 **`current` 宏** 来高效访问当前进程的 `struct task_struct`。  
在多处理器系统中，**每个 CPU 都有一个独立的变量存储指向当前 `task_struct` 的指针**，确保了多核环境下的快速访问。

![images/lec3-current-smp.png](images/lec3-current-smp.png)

# 上下文切换

![images/lec3-context-switch.png](images/lec3-context-switch.png)

在发生上下文切换之前，我们必须进行内核转换，这可以通过系统调用或中断来实现。此时，用户空间的寄存器会保存在内核堆栈上。在某个时刻，可能会调用 schedule() 函数，该函数决定从线程 T0 切换到线程 T1（例如，因为当前线程正在阻塞等待 I/O 操作完成，或者因为它的时间片已经耗尽）。

此时，context_switch() 函数将执行特定于体系结构的操作，并在需要时切换地址空间：

```c
static __always_inline struct rq *
context_switch(struct rq *rq, struct task_struct *prev,
         struct task_struct *next, struct rq_flags *rf)
{
    prepare_task_switch(rq, prev, next);

    /*
     * paravirt 中，这与 switch_to 中的 exit 配对，
     * 将页表重载和后端切换合并为一个超级调用（hypercall）。
     */
    arch_start_context_switch(prev);

    /*
     * kernel -> kernel   lazy + transfer active
     *   user -> kernel   lazy + mmgrab() active
     *
     * kernel ->   user   switch + mmdrop() active
     *   user ->   user   switch
     */
    if (!next->mm) {                                // 到内核
        enter_lazy_tlb(prev->active_mm, next);

        next->active_mm = prev->active_mm;
        if (prev->mm)                           // 来自用户
            mmgrab(prev->active_mm);
        else
            prev->active_mm = NULL;
    } else {                                        // 到用户
        membarrier_switch_mm(rq, prev->active_mm, next->mm);
        /*
         * sys_membarrier() 在设置 rq->curr / membarrier_switch_mm() 和返回用户空间之间需要一个 smp_mb()。
         *
         * 下面通过 switch_mm() 或者在 'prev->active_mm == next->mm' 的情况下通过 finish_task_switch() 的 mmdrop() 来提供这个功能。
         */
        switch_mm_irqs_off(prev->active_mm, next->mm, next);

        if (!prev->mm) {                        // 来自内核
            /* 在 finish_task_switch() 中进行 mmdrop()。 */
            rq->prev_mm = prev->active_mm;
            prev->active_mm = NULL;
        }
    }

    rq->clock_update_flags &= ~(RQCF_ACT_SKIP|RQCF_REQ_SKIP);

    prepare_lock_switch(rq, next, rf);

    /* 在这里我们只切换寄存器状态和堆栈。 */
    switch_to(prev, next, prev);
    barrier();

    return finish_task_switch(prev);
  }
...
```

它将调用**特定于架构**的 switch_to 宏实现来**切换寄存器状态和内核堆栈**。请注意，寄存器被保存在堆栈上，并且堆栈指针被保存在任务结构体中：

```c
#define switch_to(prev, next, last)               \
do {                                              \
    ((last) = __switch_to_asm((prev), (next)));   \
} while (0)


/*
 * %eax: prev task
 * %edx: next task
 */
.pushsection .text, "ax"
SYM_CODE_START(__switch_to_asm)
    /*
     * 保存被调用者保存的寄存器
     * 其必须与 struct inactive_task_frame 中的顺序匹配
     */
    pushl   %ebp
    pushl   %ebx
    pushl   %edi
    pushl   %esi
    /*
     * 保存标志位以防止 AC 泄漏。如果 objtool 支持 32 位，则可以消除此项需求，以验证 STAC/CLAC 的正确性。
     */
    pushfl

    /* 切换堆栈 */
    movl    %esp, TASK_threadsp(%eax)
    movl    TASK_threadsp(%edx), %esp

  #ifdef CONFIG_STACKPROTECTOR
    movl    TASK_stack_canary(%edx), %ebx
    movl    %ebx, PER_CPU_VAR(stack_canary)+stack_canary_offset
  #endif

  #ifdef CONFIG_RETPOLINE
    /*
     * 当从较浅的调用堆栈切换到较深的堆栈时，RSB 可能会下溢或使用填充有用户空间地址的条目。
     * 在存在这些问题的 CPU 上，用捕获推测执行的条目覆盖 RSB，以防止攻击。
     */
    FILL_RETURN_BUFFER %ebx, RSB_CLEAR_LOOPS, X86_FEATURE_RSB_CTXSW
    #endif

    /* 恢复任务的标志位以恢复 AC 状态。 */
    popfl
    /* 恢复被调用者保存的寄存器 */
    popl    %esi
    popl    %edi
    popl    %ebx
    popl    %ebp

    jmp     __switch_to
  SYM_CODE_END(__switch_to_asm)
  .popsection
```

其中RIP没有在该函数中显式保存。

# 阻塞和唤醒

## 任务状态

![images/lec3-task-status.png](images/lec3-task-status.png)

## 阻塞任务

1. 将当前线程**状态设置**为 TASK_UINTERRUPTIBLE 或 TASK_INTERRUPTIBLE；
2. 将任务**添加到等待队列**中；
3. 调用调度程序，从 READY 队列中**选择一个新任务**；
4. 进行**上下文切换**到新任务。

内核函数wait_event负责阻塞。其中，等待队列（wait_queue）是带任务结构体指针的链表。

```c
/**
 * wait_event - 在条件满足之前使当前进程休眠
 * @wq_head: 等待队列头
 * @condition: 需要等待的条件表达式
 *
 * 该宏会让当前进程进入不可中断的睡眠状态（TASK_UNINTERRUPTIBLE），直到
 * 条件 @condition 为真为止。在每次唤醒等待队列 @wq_head 时，都会检查
 * @condition。如果 @condition 已经为真，则直接退出。
 *
 * 在任何可能改变条件结果的代码路径中，调用者需要显式调用 wake_up()。
 */
#define wait_event(wq_head, condition)            \
do {                                              \
    might_sleep();                                /* 确保当前上下文允许睡眠 */ \
    if (condition)                                /* 如果条件已满足，不需要等待 */ \
        break;                                    \
    __wait_event(wq_head, condition);             /* 进入实际的等待逻辑 */ \
} while (0)

/**
 * __wait_event - 实现不可中断的等待逻辑
 * @wq_head: 等待队列头
 * @condition: 条件表达式
 *
 * 调用底层等待实现，并通过不可中断的方式（TASK_UNINTERRUPTIBLE）睡眠。
 */
#define __wait_event(wq_head, condition)                                  \
    (void)___wait_event(wq_head, condition, TASK_UNINTERRUPTIBLE, 0, 0,   \
                        schedule())

/**
 * ___wait_event - 等待的底层实现，支持更复杂的操作
 * @wq_head: 等待队列头
 * @condition: 条件表达式
 * @state: 进程的目标睡眠状态
 * @exclusive: 是否是独占等待
 * @ret: 默认返回值
 * @cmd: 等待期间需要执行的指令
 *
 * 等待过程中，通过循环检查 @condition 的值。如果条件满足或者进程
 * 被唤醒，退出循环。如果设置了 @state 为 TASK_INTERRUPTIBLE 并且
 * 有信号到达，则可能会中断等待。
 */
#define ___wait_event(wq_head, condition, state, exclusive, ret, cmd)    \
({                                                                       \
    __label__ __out;                                                     \
    struct wait_queue_entry __wq_entry;                                  \
    long __ret = ret; /* 返回值 */                                       \
                                                                         \
    init_wait_entry(&__wq_entry, exclusive ? WQ_FLAG_EXCLUSIVE : 0);     \
    for (;;) {                                                           \
        long __int = prepare_to_wait_event(&wq_head, &__wq_entry, state);\
                                                                         \
        if (condition)                                                   \
            break;                                                       \
                                                                         \
        if (___wait_is_interruptible(state) && __int) {                  \
            __ret = __int;                                               \
            goto __out;                                                  \
        }                                                                \
                                                                         \
        cmd; /* 执行传入的指令，如 schedule() */                        \
    }                                                                    \
    finish_wait(&wq_head, &__wq_entry);                                  \
__out:                                                                   \
    __ret;                                                               \
})

/**
 * init_wait_entry - 初始化等待队列条目
 * @wq_entry: 等待队列条目
 * @flags: 条目标志
 *
 * 设置条目的初始值，包括当前任务、回调函数和链表初始化。
 */
void init_wait_entry(struct wait_queue_entry *wq_entry, int flags)
{
    wq_entry->flags = flags;                      /* 设置标志位 */
    wq_entry->private = current;                  /* 关联到当前任务 */
    wq_entry->func = autoremove_wake_function;    /* 唤醒时自动移除的回调函数 */
    INIT_LIST_HEAD(&wq_entry->entry);             /* 初始化链表节点 */
}

/**
 * prepare_to_wait_event - 将当前任务加入等待队列
 * @wq_head: 等待队列头
 * @wq_entry: 等待队列条目
 * @state: 目标睡眠状态
 *
 * 检查当前任务是否有挂起的信号。如果有信号，且状态允许中断，则退出等待。
 * 否则，将当前任务加入等待队列。
 */
long prepare_to_wait_event(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry, int state)
{
    unsigned long flags;
    long ret = 0;

    spin_lock_irqsave(&wq_head->lock, flags); /* 获取等待队列锁 */
    if (signal_pending_state(state, current)) {
        /* 如果有信号挂起并且状态允许中断，退出等待 */
        list_del_init(&wq_entry->entry); /* 从队列中移除 */
        ret = -ERESTARTSYS;             /* 返回错误码 */
    } else {
        if (list_empty(&wq_entry->entry)) {
            /* 如果条目未加入队列，则根据是否独占等待加入相应位置 */
            if (wq_entry->flags & WQ_FLAG_EXCLUSIVE)
                __add_wait_queue_entry_tail(wq_head, wq_entry);
            else
                __add_wait_queue(wq_head, wq_entry);
        }
        set_current_state(state); /* 设置当前任务状态 */
    }
    spin_unlock_irqrestore(&wq_head->lock, flags);

    return ret;
}

/**
 * __add_wait_queue - 将等待条目加入队列头部
 * @wq_head: 等待队列头
 * @wq_entry: 等待队列条目
 */
static inline void __add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
    list_add(&wq_entry->entry, &wq_head->head); /* 加入链表头部 */
}

/**
 * __add_wait_queue_entry_tail - 将等待条目加入队列尾部
 * @wq_head: 等待队列头
 * @wq_entry: 等待队列条目
 */
static inline void __add_wait_queue_entry_tail(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
    list_add_tail(&wq_entry->entry, &wq_head->head); /* 加入链表尾部 */
}

/**
 * finish_wait - 清理等待队列中的任务
 * @wq_head: 等待队列头
 * @wq_entry: 等待队列条目
 *
 * 将任务状态设置为 TASK_RUNNING，并从等待队列中移除任务（如果仍在队列中）。
 */
void finish_wait(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
    unsigned long flags;

    __set_current_state(TASK_RUNNING); /* 恢复任务为运行状态 */
    if (!list_empty_careful(&wq_entry->entry)) { /* 检查条目是否仍在队列中 */
        spin_lock_irqsave(&wq_head->lock, flags); /* 获取锁 */
        list_del_init(&wq_entry->entry);         /* 从队列中移除 */
        spin_unlock_irqrestore(&wq_head->lock, flags);
    }
}
```

## 唤醒任务

wake_up用于唤醒任务：
1. 从等待队列中选择一个任务；
2. 将任务状态设置为 TASK_READY；
3. 将任务插入调度器的 READY 队列中；
4. 在 SMP 系统上，这是一个复杂的操作：每个处理器都有自己的队列，队列需要平衡，需要向 CPU 发送信号。

```c
/**
 * wake_up - 唤醒在等待队列上阻塞的线程
 * @x: 等待队列头
 *
 * 调用 __wake_up() 来唤醒等待队列上的线程，使用默认的唤醒模式和参数。
 * 默认为 TASK_NORMAL 模式，唤醒一个或多个任务（nr_exclusive 设置为 1），
 * 唤醒时没有额外的关键字传递给唤醒函数。
 */
#define wake_up(x) __wake_up(x, TASK_NORMAL, 1, NULL)

/**
 * __wake_up - 唤醒在等待队列上阻塞的线程
 * @wq_head: 等待队列头
 * @mode: 唤醒模式，决定哪些任务将被唤醒
 * @nr_exclusive: 唤醒的独占任务数，如果为 1，则唤醒 1 个独占任务，否则唤醒所有任务
 * @key: 唤醒函数需要的额外参数
 *
 * 该函数通过锁住等待队列，确保唤醒操作的原子性，然后唤醒等待队列中的一个或多个任务。
 * 如果存在独占唤醒要求，确保唤醒一个独占任务。
 */
void __wake_up(struct wait_queue_head *wq_head, unsigned int mode,
               int nr_exclusive, void *key) {
    __wake_up_common_lock(wq_head, mode, nr_exclusive, 0, key);
}

/**
 * __wake_up_common_lock - 处理唤醒操作的核心函数
 * @wq_head: 等待队列头
 * @mode: 唤醒模式，决定哪些任务将被唤醒
 * @nr_exclusive: 唤醒的独占任务数
 * @wake_flags: 唤醒时的标志
 * @key: 唤醒函数需要的额外参数
 *
 * 该函数通过加锁等待队列来确保唤醒操作的原子性，遍历等待队列并调用各个任务的唤醒函数。
 * 如果唤醒了独占任务并且已达到所要求的数量，则停止唤醒操作。
 */
static void __wake_up_common_lock(struct wait_queue_head *wq_head, unsigned int mode,
                                  int nr_exclusive, int wake_flags, void *key) {
    unsigned long flags;
    wait_queue_entry_t bookmark;

    bookmark.flags = 0;
    bookmark.private = NULL;
    bookmark.func = NULL;
    INIT_LIST_HEAD(&bookmark.entry); /* 初始化书签 */

    do {
        spin_lock_irqsave(&wq_head->lock, flags);  /* 获取队列锁 */
        nr_exclusive = __wake_up_common(wq_head, mode, nr_exclusive, wake_flags, key, &bookmark);
        spin_unlock_irqrestore(&wq_head->lock, flags); /* 解锁队列 */
    } while (bookmark.flags & WQ_FLAG_BOOKMARK); /* 如果需要，继续扫描队列 */
}

/**
 * __wake_up_common - 唤醒等待队列中的任务
 * @wq_head: 等待队列头
 * @mode: 唤醒模式，决定哪些任务将被唤醒
 * @nr_exclusive: 唤醒的独占任务数
 * @wake_flags: 唤醒时的标志
 * @key: 唤醒函数需要的额外参数
 * @bookmark: 用于继续扫描队列的书签
 *
 * 该函数是核心的唤醒逻辑，遍历等待队列中的任务，并根据给定的唤醒模式唤醒任务。
 * 如果遇到已标记为独占的任务并且唤醒数量已达到要求，则停止唤醒。
 */
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
                            int nr_exclusive, int wake_flags, void *key,
                            wait_queue_entry_t *bookmark) {
    wait_queue_entry_t *curr, *next;
    int cnt = 0;

    lockdep_assert_held(&wq_head->lock); /* 确保获取了锁 */

    if (bookmark && (bookmark->flags & WQ_FLAG_BOOKMARK)) {
        curr = list_next_entry(bookmark, entry); /* 获取下一个任务 */
        list_del(&bookmark->entry);  /* 删除书签 */
        bookmark->flags = 0;
    } else {
        curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry); /* 获取队列中的第一个任务 */
    }

    if (&curr->entry == &wq_head->head) 
        return nr_exclusive;  /* 如果队列为空，则返回唤醒数量 */

    list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {  /* 遍历队列 */
        unsigned flags = curr->flags;
        int ret;

        if (flags & WQ_FLAG_BOOKMARK)
            continue; /* 跳过已标记为书签的任务 */

        ret = curr->func(curr, mode, wake_flags, key); /* 调用任务的唤醒函数 */
        if (ret < 0)
            break;  /* 如果唤醒失败，退出循环 */

        if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
            break;  /* 如果是独占唤醒并且唤醒任务数已达到要求，退出循环 */

        if (bookmark && (++cnt > WAITQUEUE_WALK_BREAK_CNT) &&
            (&next->entry != &wq_head->head)) {
            bookmark->flags = WQ_FLAG_BOOKMARK;  /* 设置书签，用于继续扫描队列 */
            list_add_tail(&bookmark->entry, &next->entry);  /* 将书签加到队列尾部 */
            break;  /* 退出当前循环，继续扫描 */
        }
    }

    return nr_exclusive;
}

/**
 * autoremove_wake_function - 唤醒并移除任务
 * @wq_entry: 等待队列条目
 * @mode: 唤醒模式
 * @sync: 唤醒标志
 * @key: 唤醒所需的额外参数
 *
 * 调用默认的唤醒函数，如果唤醒成功，则从队列中移除该任务。
 */
int autoremove_wake_function(struct wait_queue_entry *wq_entry, unsigned mode, int sync, void *key) {
    int ret = default_wake_function(wq_entry, mode, sync, key);  /* 调用默认唤醒函数 */

    if (ret)
        list_del_init_careful(&wq_entry->entry);  /* 唤醒后移除任务 */
    
    return ret;
}

/**
 * default_wake_function - 默认的唤醒函数
 * @curr: 当前等待队列条目
 * @mode: 唤醒模式
 * @wake_flags: 唤醒标志
 * @key: 唤醒所需的额外参数
 *
 * 该函数调用 `try_to_wake_up` 尝试唤醒给定的任务，并返回唤醒结果。
 */
int default_wake_function(wait_queue_entry_t *curr, unsigned mode, int wake_flags,
                          void *key) {
    WARN_ON_ONCE(IS_ENABLED(CONFIG_SCHED_DEBUG) && wake_flags & ~WF_SYNC);
    return try_to_wake_up(curr->private, mode, wake_flags);  /* 调用 try_to_wake_up 唤醒任务 */
}

/**
 * try_to_wake_up - 尝试唤醒指定任务
 * @p: 要唤醒的任务
 * @state: 任务的目标状态掩码
 * @wake_flags: 唤醒标志
 *
 * 该函数尝试将任务的状态从睡眠状态切换为运行状态，并将其重新加入运行队列。
 * 如果任务的状态已经满足，返回 false；如果任务被成功唤醒，返回 true。
 *
 * 该函数在访问 @p->state 之前会触发内存屏障，确保任务的状态被正确更新。
 */
static int try_to_wake_up(struct task_struct *p, unsigned int state, int wake_flags) {
    // 内部实现代码，具体行为包括更新任务状态、处理迁移等
    ...
}
```

# 任务抢占

任务抢占是指系统中运行的任务可以被操作系统中断，以调度其他任务执行。这种机制确保了系统资源的公平分配和实时响应性。

## 非抢占式内核

### 工作机制
1. **时间片检查**：  
   每次时钟滴答（`timer tick`）发生时，内核会检查当前任务是否已经耗尽了分配的时间片。时间片是内核分配给任务的一段运行时间，用于确保多任务的公平性。
   
2. **标志位设置**：  
   如果时间片用完，内核会在中断上下文中设置一个标志位，标记当前任务需要被调度。

3. **调度检查**：  
   在任务从内核返回用户空间之前[2]，内核会检查这个标志位。如果标志位已设置，内核会调用调度器函数（`schedule()`），切换到另一个任务。

### 特点
- **内核模式运行不受干扰**：  
  在非抢占式内核中，任务在内核模式下（例如执行系统调用时）不会被抢占。这意味着任务可以在内核中**以更简单的方式访问共享资源**，因为无需担心被其他任务打断。

## 抢占式内核

### 工作机制
1. **内核模式抢占**：  
   在抢占式内核中，任务即使运行在内核模式下（例如执行系统调用时），也可能被其他任务抢占。这种抢占是为了提高系统的实时性。

2. **同步原语控制**：  
   为了避免在抢占过程中破坏内核的状态，内核提供了如下**同步原语**：
   - **`preempt_disable()`**：禁止抢占。当前任务进入关键区域时调用，确保此区域内不会发生上下文切换。
   - **`preempt_enable()`**：重新启用抢占。在任务离开关键区域时调用，允许其他任务获取CPU。
   
   为了简化代码逻辑，Linux内核设计了自动禁用抢占的机制：当任务获取自旋锁时，内核会自动调用`preempt_disable()`，释放自旋锁时调用`preempt_enable()`。

3. **抢占触发检查**：  
   与非抢占式内核类似，内核会在时间片耗尽或其他抢占条件满足时设置一个标志位。每次`preempt_enable()`或`spin_unlock()`重新激活抢占时，内核会检查这个标志位。如果标志位设置，内核会调用调度器切换任务。

### 特点
- **实时性更高**：  
  抢占式内核可以在任意时刻响应调度请求，从而提高系统的实时性能。

## 非抢占式与抢占式内核对比

| 特性                    | 非抢占式内核                             | 抢占式内核                             |
|-------------------------|------------------------------------------|----------------------------------------|
| **任务抢占时机**       | 仅在用户模式运行的任务可被抢占           | 用户模式和内核模式任务均可被抢占       |
| **同步问题**           | 无需在内核模式下使用复杂同步原语         | 需要同步原语保护关键区域               |
| **实时性**             | 较低                                     | 较高                                   |
| **复杂性**             | 实现相对简单                             | 需要更多代码处理抢占逻辑               |

# 进程上下文

**进程上下文**是 Linux 内核中运行环境的一种模式，它的核心特点是与具体的用户进程相关联。内核在处理系统调用或与用户进程交互时，通常运行在进程上下文中。以下对其特点和行为进行详细解释：

## 主要属性

### `current`指针的作用
- **`current`变量**：  
  在进程上下文中，内核通过`current`指针访问当前进程的描述符（`task_struct`）。
  - 该指针由内核维护，用于标识当前正在运行的进程。
  - 内核中许多子系统和驱动程序通过`current`获取当前进程的数据，比如进程ID（PID）、用户信息、打开的文件等。

### 可睡眠（允许阻塞）
- 在进程上下文中，内核允许任务**睡眠**，即：
  - 任务可以主动放弃CPU，等待某个条件（如I/O完成）。
  - 这是通过内核的等待队列（wait queues）和调度机制实现的。
- 睡眠的典型场景：
  - 等待设备完成I/O操作。
  - 等待某个锁被释放。

- **与中断上下文对比**：  
  在中断上下文中，任务不能睡眠，因为中断服务必须尽快完成，不能影响系统实时性。

### 用户空间访问能力
- 在进程上下文中，内核可以访问用户空间的数据和资源（例如读取用户空间传入的缓冲区数据）。
- **限制**：
  - 当内核运行在**内核线程上下文**中时（即当前任务为内核线程），因为内核线程没有关联的用户空间，所以无法直接访问用户空间数据。

## 常见用途
进程上下文是内核处理用户进程请求的主要模式。以下是一些典型的应用场景：

- 系统调用
  - 用户进程通过系统调用进入内核态，内核为该进程服务。此时内核处于进程上下文中。
  - 例如：
    - `read()`系统调用中，内核会从文件中读取数据并写入用户缓冲区。
    - 这些操作通过`current`访问当前用户进程的数据。
- 阻塞I/O
  - 当用户进程发起需要等待的操作（如从磁盘读取数据），任务会进入睡眠状态，直到条件满足后被唤醒。
- 信号处理
  - 当一个信号需要递送到某个用户进程时，内核通过进程上下文访问该进程，并将信号处理函数传递给用户空间执行。

## 进程上下文与其他上下文的对比

| **属性**           | **进程上下文**                                      | **中断上下文**                              | **内核线程上下文**                        |
|--------------------|----------------------------------------------------|--------------------------------------------|-------------------------------------------|
| **是否关联进程**   | 是（通过`current`指针访问当前进程）                  | 否                                         | 否（没有关联用户空间）                    |
| **是否允许睡眠**   | 是                                                  | 否                                         | 是                                        |
| **访问用户空间**   | 可以（如果非内核线程上下文）                         | 不可以                                     | 不可以                                   |
| **典型应用场景**   | 系统调用、阻塞I/O、信号处理                          | 硬件中断、软中断、任务let                   | 后台任务、驱动程序、内核功能模块           |

## 内核线程

内核线程（Kernel Thread）是 Linux 内核中的一种特殊任务，用于**在内核态执行长时间运行的任务**，尤其是那些可能需要阻塞的操作。以下是对内核线程与进程上下文关系的详细说明。

### 为什么需要内核线程？
- **阻塞需求**：  
  有时内核需要执行一些可能阻塞的任务（如等待I/O完成），但普通的中断上下文或定时器上下文不能满足这种需求，因为它们**不能阻塞**。
  
- **背景任务**：  
  内核需要一些后台任务来完成独立于用户进程的工作，例如定期清理内存、刷新文件缓存等。这些任务与具体用户进程无关，但又需要内核的调度支持。

- **避免用户态干扰**：  
  内核线程运行在完全的内核模式下，与用户态任务无关，且不受用户进程的调度和资源限制影响。

### 什么是内核线程？
内核线程是内核中一种特殊的进程，它有以下特点：
- **没有用户空间**：
  - 内核线程不与用户空间绑定（即没有用户地址空间）。
  - 不使用用户态的资源，例如文件描述符、虚拟地址空间等。

- **运行在进程上下文中**：
  - 虽然没有用户态，但内核线程仍然运行在**进程上下文**中[3]，因此它可以睡眠或阻塞。

- **任务实现**：
  - 内核线程的行为类似普通进程，但它的功能仅限于内核中。
  - 它的代码通常由内核核心或设备驱动程序提供。

### 内核线程与普通进程的区别

| **属性**               | **普通进程**                     | **内核线程**                   |
|------------------------|-----------------------------------|---------------------------------|
| **是否有用户空间**     | 是（用户空间+内核空间）           | 否（仅有内核空间）             |
| **是否可以睡眠**       | 是                               | 是                             |
| **调度机制**           | 用户态和内核态调度               | 仅在内核态下调度               |
| **用途**               | 用户任务                         | 内核任务（如设备驱动、后台维护） |
| **典型操作**           | 文件操作、系统调用等             | 定期清理缓存、内核定时任务等   |

---

### 典型应用场景

- **驱动程序中的阻塞操作**
  - 某些设备驱动程序需要等待设备响应，例如等待硬件完成一个指令执行。这种情况下，可以使用内核线程完成任务，而无需占用中断上下文。
- **内核后台维护任务**
  - 内核中许多后台任务使用内核线程，例如：
    - 内存回收线程（`kswapd`）：负责定期回收页面。
    - 磁盘写缓冲刷新线程（`pdflush`/`flush`）：负责将脏页写回磁盘。
    - CPU负载均衡线程（`ksoftirqd`）：处理软中断。
- **定制任务**
  - 开发者可以创建自定义的内核线程，用于特定场景，例如监控内核状态或定期执行某些操作。

---

### 如何实现内核线程？

#### **创建内核线程**
使用`kthread`相关的API创建内核线程：
1. **创建线程**：  
   使用`kthread_create()`创建线程，并指定启动函数。
   ```c
   struct task_struct *task;
   task = kthread_create(thread_function, NULL, "my_thread");
   ```
2. **启动线程**：  
   使用`wake_up_process()`启动线程。
   ```c
   wake_up_process(task);
   ```

#### **线程的主函数**
内核线程的主函数通常是一个循环，执行特定任务，并可以阻塞等待某些条件：
```c
int thread_function(void *data) {
    while (!kthread_should_stop()) {
        // 执行某些任务
        msleep(1000); // 阻塞1秒
    }
    return 0;
}
```

#### **停止线程**
使用`kthread_stop()`安全地停止线程：
```c
kthread_stop(task);
```

# 注释

> [1] https://docs.kernel.org/dev-tools/gdb-kernel-debugging.html
> 
> [2] 当一个任务运行在内核模式时（例如执行系统调用期间），即便时间片耗尽，内核也不会立即调度其他任务。
>
> [3] 内核线程运行在进程上下文中，因为它需要像普通进程一样被调度、睡眠和阻塞，同时利用进程相关的内核资源和机制，但不涉及用户空间资源。