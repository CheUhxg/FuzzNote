## 常识

### seccomp

seccomp是一种内核安全机制，允许“程序”限制对系统调用的访问。系统调用可以完全禁止(不可能调用它)，也可以部分禁止(过滤参数)。它是使用称为seccomp过滤器的BPF规则(内核中编译的“程序”)设置的。

如果一个使用seccomp的程序调用了系统调用，内核将会检查thread_info的标志是否包含_TIF_WORK_SYSCALL_ENTRY标志集(TIF_SECCOMP是其中一个)。如果包含的话，则调用syscall_trace_enter()。

```c
long syscall_trace_enter(struct pt_regs *regs)
{
    long ret = 0;

    if (test_thread_flag(TIF_SINGLESTEP))
        regs->flags |= X86_EFLAGS_TF;

    /* do the secure computing check first */
    secure_computing(regs->orig_ax);            // <----- "rax" holds the syscall number

  // ...
}

static inline void secure_computing(int this_syscall)
{
    if (unlikely(test_thread_flag(TIF_SECCOMP)))      // <----- check the flag again
        __secure_computing(this_syscall);
}
```

如果系统调用是被禁止的，该进程将会收到一个SIGKILL信号。

### thread_info

thread_info被称作迷你进程描述符，存放在内核线程栈中。

```c
// [arch/x86/include/asm/thread_info.h]

struct thread_info {
    struct task_struct    *task;
    struct exec_domain    *exec_domain;
    __u32                 flags;
    __u32                 status;
    __u32                 cpu;
    int                   preempt_count;
    mm_segment_t          addr_limit;
    struct restart_block  restart_block;
    void __user           *sysenter_return;
#ifdef CONFIG_X86_32
    unsigned long         previous_esp;
    __u8                  supervisor_stack[0];
#endif
    int                   uaccess_err;
};
```

其中重要的字段有：

* task:指向该thread_info的task_struct的指针。
  * thread_info和task_struct其实是双向绑定，task_struct的stack指针指向thread_info。
* flags:保留诸如_TIF_NEED_RESCHED或_TIF_SECCOMP的标志。
* addr_limit:内核角度的“最高”用户域虚拟地址，用于“软件保护机制”。

使用宏get_current()可以得到thread_info对应的task_struct指针。

```c
#define get_current() (current_thread_info()->task)
```

### 进程描述符

每一个线程对应一个进程描述符task_struct，宏current指向当前任务的task_struct。

```c
// [include/linux/sched.h]

struct task_struct {
    volatile long state;            // process state (running, stopped, ...)
    void *stack;                    // task's stack pointer
    int prio;                       // process priority
    struct mm_struct *mm;           // memory address space
    struct files_struct *files;     // open file information
    const struct cred *cred;        // credentials
  // ...
};
```

### 文件描述符

文件描述符可以表示Linux系统上的任意文件，每个文件描述符对应一个file结构体。

```c
// [include/linux/fs.h]

struct file {
    loff_t                            f_pos;            // "cursor" while reading file
    atomic_long_t                     f_count;          // object's reference counter
    const struct file_operations      *f_op;            // virtual function table (VFT) pointer
  void                              *private_data;      // used by file "specialization"
  // ...
};
```

文件描述符到file结构体的映射由文件描述符表(FDT)来实现，可能存在多个文件描述符指向同一个file结构体。FDT存储在fdtable结构体中，这是个file结构体指针数组，使用文件描述符进行索引。

```c
// [include/linux/fdtable.h]

struct fdtable {
    unsigned int max_fds;
    struct file ** fd;      /* current fd array */
  // ...
};
```

### 进程和文件的关联

将文件描述符表与进程关联起来的是files_struct结构体。

```c
// [include/linux/fdtable.h]

struct files_struct {
    atomic_t count;           // reference counter
    struct fdtable *fdt;      // pointer to the file descriptor table
  // ...
};
```

由于一个files_struct可以在多个线程(task_struct)中共享，所以files_struct**以指针的形式**保存在task_struct的files字段中。

### 虚函数表

虚函数表(VFT)是主要由函数指针组成的结构体，其中比较出名的VFT是file_operations。

```c
// [include/linux/fs.h]

struct file_operations {
    ssize_t (*read) (struct file *, char __user *, size_t, loff_t *);
    ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);
    int (*open) (struct inode *, struct file *);
    int (*release) (struct inode *, struct file *);
  // ...
};
```

这样一来就可以根据文件本身的性质来定义是否实现某功能。

```c
if (file->f_op->read)
    ret = file->f_op->read(file, buf, count, pos);
```

### Socket, Sock 和 SKB

在socket创建期间，即调用socket()，将创建一个新的file结构体，并将其文件操作字段设置为socket_file_ops。

```c
// [net/socket.c]

static const struct file_operations socket_file_ops = {
    .read = sock_aio_read,      // <---- calls sock->ops->recvmsg()
    .write =    sock_aio_write, // <---- calls sock->ops->sendmsg()
    .llseek =   no_llseek,      // <---- returns an error
  // ...
}
```

由于socket实际上实现了socket API(connect()、bind()、accept()、listen()...)，因此它们嵌入了一个类型为struct proto_ops的特殊虚函数表(vft)。每种类型的套接字(例如AF_INET、AF_NETLINK)都实现自己的proto_ops。

```c
// [include/linux/net.h]

struct proto_ops {
    int     (*bind)    (struct socket *sock, struct sockaddr *myaddr, int sockaddr_len);
    int     (*connect) (struct socket *sock, struct sockaddr *vaddr,  int sockaddr_len, int flags);
    int     (*accept)  (struct socket *sock, struct socket *newsock, int flags);
  // ...
}
```

执行如上系统调用(例如bind())时，内核的处理过程如下：

1. 从文件描述符表中获得file结构体指针；
2. 从file结构体中获得socket结构体指针；
3. 调用专门的proto_ops回调函数(例如sock->ops->bind())。

struct socket具有指向struct sock对象的指针，该指针通常由套接字协议操作(proto_ops)使用。struct socket是连接struct file和struct sock的中间结构体。

```c
// [include/linux/net.h]

struct socket {
    struct file     *file;
    struct sock     *sk;
    const struct proto_ops  *ops;
  // ...
};
```

struct sock用于以通用方式保持接收/发送缓冲区。当通过网卡接收到数据包时，驱动程序将网络数据包加入到*sock接收缓冲区*中，直到程序决定接收它(recvmsg())。反过来，当程序想要发送数据(sendmsg())时，网络数据包被加入到*sock发送缓冲区*。一有机会，网卡将取出该数据包并发送。

上述网络数据包就是struct sk_buff(SKB)，缓冲区就是由struct sk_buff组成的双向链表。

```c
// [include/linux/sock.h]

struct sock {
    int         sk_rcvbuf;    // theorical "max" size of the receive buffer
    int         sk_sndbuf;    // theorical "max" size of the send buffer
    atomic_t        sk_rmem_alloc;  // "current" size of the receive buffer
    atomic_t        sk_wmem_alloc;  // "current" size of the send buffer
    struct sk_buff_head sk_receive_queue;   // head of doubly-linked list
    struct sk_buff_head sk_write_queue;     // head of doubly-linked list
    struct socket       *sk_socket; // socket <-> sock
  // ...
}
```

> struct sock对象通常称为sk，而struct socket对象通常称为sock。

### Netlink Socket

Netlink Socket是socket的一种，该地址族(AF_NETLINK)负责内核和用户之间的通信：

* 修改路由表(NETLINK_ROUTE)
* 接收SELinux事件通知(NETLINK_SELINUX)
* 与其他用户进程通信(NETLINK_USERSOCK)

创建Netlink Socket时，顶层仍使用socket(通用套接字)，使用BSD样式的套接字操作netlink_ops。

```c
// [net/netlink/af_netlink.c]

static const struct proto_ops netlink_ops = {
    .bind =     netlink_bind,
    .accept =   sock_no_accept,     // <--- calling accept() on netlink sockets leads to EOPNOTSUPP error
    .sendmsg =  netlink_sendmsg,
    .recvmsg =  netlink_recvmsg,
  // ...
}
```

在使用netlink的情况下，sock对应的是struct netlink_sock(更像sock的子类)。

```c
// [include/net/netlink_sock.h]

struct netlink_sock {
    /* struct sock has to be the first member of netlink_sock */
    struct sock     sk;
    u32         pid;
    u32         dst_pid;
    u32         dst_group;
  // ...
};
```

> sk是netlink_sock的**第一个成员(地址相同)**，就可以实现释放指针＆netlink_sock.sk实际上释放了整个netlink_sock对象。

### 引用计数

在Linux内核中，使用refcounter作为引用计数，类型为atomic_t。使用原子操作来修改：

1. atomic_inc()：减
2. atomic_add()：加
3. atomic_dec_and_test()：减一并判断是否为0

一般来说\*_get()用于增加引用，\*_put()用于减少引用。

> 仅仅是习惯，比如skb_put()并不会减少引用。

### 运行&等待队列

struct rq(run queue)是调度器最重要的数据结构之一。运行队列中的每个任务都将由CPU执行，每个CPU都有自己的运行队列（允许真正的多任务处理）。运行队列具有一个任务(由调度器选择在指定的CPU上运行)列表。还具有统计信息，使调度器做出“公平”选择并最终重新平衡每个cpu之间的负载（即cpu迁移）。

```c
// [kernel/sched.c]

struct rq {
  unsigned long nr_running;   // <----- statistics
  u64 nr_switches;            // <----- statistics
  struct task_struct *curr;   // <----- the current running task on the cpu
  // ...
};
```

> deactivate_task()函数将任务从运行队列中移出，任务阻塞。与之相反，activate_task()将任务加入到运行队列中。

任务等待资源或特殊事件非常普遍。例如，如果运行服务器(客户端-服务器（Client/Server）架构里的Server)，主线程可能正在等待即将到来的连接。除非它被标记为“非阻塞”，否则accept()系统调用将阻塞主线程。也就是说，主线程将阻塞在内核中，直到其他东西唤醒它。

等待队列基本上是**由当前阻塞(等待)的任务组成的双链表**。与之相对的是运行队列。队列本身用wait_queue_head_t表示：

```c
// [include/linux/wait.h]

typedef struct __wait_queue_head wait_queue_head_t;

struct __wait_queue_head {
    spinlock_t lock;
    struct list_head task_list;
};
```

等待队列的每个元素用wait_queue_t表示。

```c
// [include/linux.wait.h]

typedef struct __wait_queue wait_queue_t;
typedef int (*wait_queue_func_t)(wait_queue_t *wait, unsigned mode, int flags, void *key);

struct __wait_queue {
    unsigned int flags;
    void *private;          
    wait_queue_func_t func;     // <----- we will get back to this
    struct list_head task_list;
};
```

生成等待队列元素的宏是DECLARE_WAITQUEUE()。

```c
// [include/linux/wait.h]

#define __WAITQUEUE_INITIALIZER(name, tsk) {                \
    .private    = tsk,                      \
    .func       = default_wake_function,            \
    .task_list  = { NULL, NULL } }

#define DECLARE_WAITQUEUE(name, tsk)                    \
    wait_queue_t name = __WAITQUEUE_INITIALIZER(name, tsk) // <----- it creates a variable!
```

使用add_wait_queue()将生成好的等待队列元素添加到等待队列中。

```c
// [kernel/wait.c]

void add_wait_queue(wait_queue_head_t *q, wait_queue_t *wait)
{
    unsigned long flags;

    wait->flags &= ~WQ_FLAG_EXCLUSIVE;
    spin_lock_irqsave(&q->lock, flags);
    __add_wait_queue(q, wait);              // <----- here
    spin_unlock_irqrestore(&q->lock, flags);
}

static inline void __add_wait_queue(wait_queue_head_t *head, wait_queue_t *new)
{
    list_add(&new->task_list, &head->task_list);
}
```

当任务等待的条件满足时，资源所有者通过__wake_up()唤醒等待的线程。

```c
// [kernel/sched.c]

/**
 * __wake_up - wake up threads blocked on a waitqueue.
 * @q: the waitqueue
 * @mode: which threads
 * @nr_exclusive: how many wake-one or wake-many threads to wake up
 * @key: is directly passed to the wakeup function
 *
 * It may be assumed that this function implies a write memory barrier before
 * changing the task state if and only if any tasks are woken up.
 */

void __wake_up(wait_queue_head_t *q, unsigned int mode,
            int nr_exclusive, void *key)
{
    unsigned long flags;

    spin_lock_irqsave(&q->lock, flags);
    __wake_up_common(q, mode, nr_exclusive, 0, key);    // <----- here
    spin_unlock_irqrestore(&q->lock, flags);
}
```

```c
// [kernel/sched.c]

    static void __wake_up_common(wait_queue_head_t *q, unsigned int mode,
          int nr_exclusive, int wake_flags, void *key)
    {
      wait_queue_t *curr, *next;

[0]   list_for_each_entry_safe(curr, next, &q->task_list, task_list) {
        unsigned flags = curr->flags;

[1]     if (curr->func(curr, mode, wake_flags, key) &&
            (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
          break;
      }
    }
```

对每个等待队列中的元素执行func回调函数，该函数是在DECLARE_WAITQUEUE宏中指定的default_wake_function。其内部调用try_to_wake_up()，try_to_wake_up()有点像schedule()的“对立面”。**schedule()将当前任务“调度出去”**，**try_to_wake_up()使其再次可调度**。也就是说，它将任务加入运行队列中并更改其状态为"TASK_RUNNING"。

### cgroup

> cgroup：control group

cgroup为系统中*运行的task*分配诸如CPU时间片、系统内存、网络带宽或这些资源的组合。用户可以监控配置的cgroup，禁止cgroup访问某些资源。

* cgroup将一组task与一个或多个*子系统*的参数关联起来。
  * 资源被定义成不同的*子系统*（如CPU子系统、Memory子系统）。
* cgroup采用*层次结构*划分资源，系统中每个task都属于层次结构的一个cgroup。
  * *层次结构*就是一组以树形态排列的cgroup。
  * 每个层次结构都对应一个*cgroup虚拟文件系统实例*。

cgroup_subsys_state(css)用于关联层次结构中cgroup和子系统，css_set将一组task绑定到cgroup。

* task可以隶属于多个cgroup，但是只能属于一个css_set。
* 由于进程可能共享资源，所以css_set可以包含多个进程。

```mermaid
graph TB
    subgraph css_set1
        css1[css1]
        css2[css2]
    end
    subgraph css_set2
        css3[css3]
    end
    m[memory_subsystem]-->mroot
    c[cpu_subsystem]-->croot
    ca[cpuacct_subsystem]-->croot
    css1-->c
    css2-->m
    css3-->ca
    subgraph Memory Hierarchiy
        mroot[memory_cgroup]-->mc1[cgrp4 80%]
        mroot-->mc2[cgrp5 30%]
        mc2-->p1(proc1)
        mc2-->p2(proc2)
        p1-->css1
        p1-->css2
        p2-->css3
    end
    subgraph CPU Hierarchiy
        croot[cpu_cgroup]-->cc1[cgrp1 40%]
        croot-->cc2[cgrp2 60%]
        croot-->cc3[cgrp3 70%]
    end
```

> 上图中百分比表示该cgroup中资源利用占比的最大值。

用户级代码可以在cgroup虚拟文件系统实例中，按照名称创建和销毁cgroup、查询task的分配情况。

* 这些操作只会影响cgroup虚拟文件系统实例对应的层次结构。
* 通过fsopen()打开cgroup虚拟文件系统，fsconfig()对文件系统结构进行配置。

### 用户命名空间

命名空间**将内核资源分区**，以便不同的进程看到不同的资源。

* 内核将资源和进程归到同一个命名空间中，每个命名空间引用的资源不同。
* 资源可能存在于多个命名空间中，包含pid、uid、文件名、接入网络名和IPC。

用户命名空间是用于隔离安全相关的资源的命名空间，包含uid、gid、keys和cap。

* 用户名称空间中有个*映射表*，可以将uid从容器的视图转换为实际系统视图。
  * 例如，容器中的uid为0时，在系统中其uid为非0值。
  * 除了uid的映射外，还有gid的映射表以及所有权检查。

### netfilter

netfilter是用于**数据包处理**的子组件。

* 支持数据包过滤、网络地址/端口转换（NA[P]T）、数据包日志记录、用户空间数据包队列和其他数据包处理。
* 如iptables和NAT server的实现。

## 技巧

* kASLR以2M为最小单位设置基地址，所以通过不断重启查看/proc/kallsyms，可以计算出某个全局变量的偏移量。

### QEMU
* 打开--enable-kvm时，gdb调试无法在断点停下。
* 打开smep/smap：-cpu <cpu-type>/+smep,+smap。

# 简写

| 缩写  | 全称                         | 说明                                           |
| ----- | ---------------------------- | ---------------------------------------------- |
| TLB   | Translation Lookaside Buffer | 用于加速虚拟地址到物理地址的转换               |
| IDT   | Interrupt Descriptor Table   | 用于存储中断和异常处理程序的地址               |
| CR3   | Control Register 3           | 用于存储当前进程的页表基地址                   |
| PGD   | Page Global Directory        | 用于管理进程的页表                             |
| PTE   | Page Table Entry             | 页表项，用于将虚拟地址映射到物理地址           |
| MMU   | Memory Management Unit       | 内存管理单元，用于实现虚拟内存和物理内存的映射 |
| DMA   | Direct Memory Access         | 直接内存访问，用于实现设备和内存之间的数据传输 |
| NUMA  | Non-Uniform Memory Access    | 非一致性内存访问，用于描述分布式内存系统       |
| PML4E | Page Map Level 4 Entry       | x86-64 架构下四级页表中的第一级                |
| PDPT  | Page Directory Pointer Table | x86-64 架构下四级页表中的第二级                |
| PD    | Page Directory               | x86-64 架构下四级页表中的第三级                |
| PT    | Page Table                   | x86-64 架构下四级页表中的第四级                |
| GDT   | Global Descriptor Table      | 存储全局段描述符的表格                         |
| LDT   | Local Descriptor Table       | 存储局部段描述符的表格                         |
| A20   | Address line 20              | 用于扩展内存寻址空间                           |
| PAE   | Physical Address Extension   | 用于扩展物理地址空间                           |
| NX    | No-Execute                   | 禁止执行内存中的代码，用于提高系统的安全性     |

希望这份对照表对您有帮助！
