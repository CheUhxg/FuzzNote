# 简介

根据内存安全发展历程，按照时间顺序，总结攻击方式以及对应的防御策略。

# 攻击以及防御策略

## 缓冲区溢出

缓冲区溢出是一种软件编码错误或漏洞，黑客可以利用它未经授权访问系统。它是最著名的软件安全漏洞之一，而且相当普遍。这在一定程度上是因为缓冲区溢出可能以各种方式发生，而用于防止溢出的技术往往容易出错。

> 缓冲区溢出包括栈溢出和堆溢出。

### 栈溢出

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而**导致与其相邻的栈中的变量的值被改变**。

发生栈溢出的基本前提
* 程序向栈上写入数据。
* 写入的数据大小超过分配的大小。

通过精心设计溢出数据，可以实现rip劫持。详细参考[栈溢出](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/#_3)。

### 堆溢出

堆溢出是指**程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数**，因而导致了数据溢出，并**覆盖到物理相邻的高地址的下一个堆块**。
* *是可使用而不是用户申请的字节数*，因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数。

堆溢出漏洞发生的基本前提
* 程序向堆上写入数据。
* 写入的数据大小超过可使用字节数。

与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此我们一般无法直接通过堆溢出来控制rip。

利用堆溢出的策略是
1. **覆盖与其物理相邻的下一个chunk的内容**：
   * prev_size
   * size：主要有三个比特位，以及该堆块真正的大小。
     * NON_MAIN_ARENA
     * IS_MAPPED
     * PREV_INUSE
     * the True chunk size
   * chunk content
2. 利用堆中的机制（如unlink等 ）来**实现任意地址写入或控制堆块中的内容**等效果，从而来控制程序的执行流，参考[堆溢出](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heapoverflow-basic/#_3)。

### 防御策略：栈破坏检查

针对栈溢出设计的栈破坏检查，可以防止栈溢出漏洞。

栈金丝雀(Stack Canaries)是放置在堆栈上的一个秘密值，它在每次程序启动时都会更改。在函数返回之前，检查堆栈指示器，如果它被修改了，程序立即退出。

栈金丝雀是由编译器生成的，位于Buffer和SFP中间。

![](https://images.contentstack.io/v3/assets/blt36c2e63521272fdc/blt5f070f8052db15bc/601c8cf44b8030688c37b8b9/StackCanaries_Fig3.png)

# 参考

* [栈溢出](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/)
* [堆溢出](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/heapoverflow-basic/)
* [stack canary](https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/)