# Linux 系统调用实现

从高层视角来看，系统调用是内核向用户应用程序提供的**服务**，它们类似于库 API，因为它们被描述为具有名称、参数和返回值的函数调用。

然而，从底层视角看的话，我们会发现系统调用实际上并不是函数调用，而是**特定的汇编指令**（与体系结构和内核相关），其功能如下：
1. 用于识别系统调用及其参数的设置信息。
2. 触发内核模式切换。
3. 获取系统调用的结果。

在 Linux 中，系统调用使用数字进行标识，系统调用的参数为机器字大小（32 位或 64 位）。最多可以有 `6` 个系统调用参数。系统调用编号和参数都存储在特定的寄存器中。在 32 位的 x86 架构中，系统调用标识符存储在 EAX 寄存器中，而参数存储在 EBX、ECX、EDX、ESI、EDI 和 EBP寄存器中。

系统库（例如 libc 库）提供了一些函数，这些函数可以执行实际的系统调用，从而便于应用程序的使用。

当用户到内核模式的转换发生时，执行流程会被中断，并传递到内核的入口点。这类似于中断和异常的处理方式（实际上，在某些架构上，这种转换正是由异常引起的）。

在用户模式和内核模式之间的切换过程中，还会将堆栈从用户堆栈切换到内核堆栈。系统调用入口点会将寄存器（其中包含来自用户空间的值，包括系统调用标识符和系统调用参数）保存在堆栈上，然后继续执行系统调用分发器（system call dispatcher）。系统调用分发器的作用是验证系统调用编号，并执行与该系统调用相关的内核函数。

总结一下，在系统调用过程中发生了以下情况：
1. 应用程序设置系统调用编号和参数，并触发陷阱（trap）指令。
2. 执行模式从用户模式切换到内核模式；CPU 切换到内核堆栈；用户堆栈和返回地址保存在内核堆栈中。
3. 内核入口点将寄存器保存在内核堆栈中。
4. 系统调用分发器识别系统调用函数并运行它。
5. 恢复用户空间寄存器并切换回用户空间（例如，调用 IRET 指令）。
6. 用户空间应用程序恢复执行。

## 系统调用表

系统调用表是系统调用分发器用于**将系统调用编号映射到内核函数**的数据结构。

```
#define __SYSCALL_I386(nr, sym, qual) [nr] = sym,

const sys_call_ptr_t ia32_sys_call_table[] = {
  [0 ... __NR_syscall_compat_max] = &sys_ni_syscall,
  #include <asm/syscalls_32.h>
};
```

```
__SYSCALL_I386(0, sys_restart_syscall)
__SYSCALL_I386(1, sys_exit)
__SYSCALL_I386(2, sys_fork)
__SYSCALL_I386(3, sys_read)
__SYSCALL_I386(4, sys_write)
#ifdef CONFIG_X86_32
__SYSCALL_I386(5, sys_open)
#else
__SYSCALL_I386(5, compat_sys_open)
#endif
__SYSCALL_I386(6, sys_close)
```

## 虚拟动态共享对象 (VDSO)

### 什么是 VDSO？
VDSO（Virtual Dynamic Shared Object，虚拟动态共享对象）是一种优化系统调用实现的机制。它的设计目标是避免 libc 必须跟踪 CPU 特性和内核版本，从而提高系统调用的效率。

### 背景
以 x86 架构为例，触发系统调用有两种常见方式：  
- **`int 0x80`**：较老的方式，性能相对较差。  
- **`sysenter`**：较新且显著更快的方式，但它有以下限制：
  - 仅适用于 **Pentium II** 及之后的处理器。
  - 需要 **2.6** 或更新版本的内核支持。  

### VDSO 的作用
通过 VDSO，**系统调用接口由内核动态生成**，无需用户程序关心底层实现方式：  
1. **内核动态生成指令**：内核会在一个特殊的内存区域内生成一系列用于触发系统调用的指令，并将其格式化为一个 ELF 共享对象。  
2. **映射到用户空间**：该内存区域会被映射到用户地址空间的末尾，供用户程序直接使用。  
3. **libc 自动使用 VDSO**：当 VDSO 存在时，`libc` 会优先使用它触发系统调用，而不需要手动配置。

### VDSO 与虚拟系统调用 (vsyscall)

VDSO 的一个有趣衍生物是 **虚拟系统调用 (vsyscall)**，它提供了一种直接在用户空间运行的“系统调用”方式。这些 vsyscall 属于 VDSO 的一部分，并依赖于内核映射的 VDSO 页面上的数据。

什么是 vsyscall？
- **直接从用户空间运行**：vsyscall 不需要通过传统的内核-用户态切换，直接从用户空间执行，进一步优化性能。  
- **VDSO 的扩展**：vsyscall 使用 VDSO 页面上提供的数据，既可以是静态的，也可以是动态更新的。

vsyscall 的两种数据类型
1. **静态数据**：无需频繁更新，由内核提供一次性数据。例如：
   - `getpid()`：提供当前进程 ID。
2. **动态更新数据**：内核通过 VDSO 页面上的读写映射实时更新。例如：
   - `gettimeofday()`：提供精确的系统时间。
   - `time()`：返回自 Unix 纪元以来的时间戳。


## 通过系统调用访问用户空间

在 Linux 内核中，访问用户空间数据时必须使用特定的 API，如 `get_user()`、`put_user()`、`copy_from_user()` 和 `copy_to_user()`。

```c
// 如果 user_ptr 无效，返回 -EFAULT
if (copy_from_user(&kernel_buffer, user_ptr, size))
    return -EFAULT;

// 如果直接使用 memcpy，则可能导致内核崩溃
memcpy(&kernel_buffer, user_ptr, size);
```

### `get_user()` 的实现

以 x86 为例，`get_user()` 是一个宏，使用内联汇编实现用户空间数据的安全访问。

```c
#define get_user(x, ptr)                                          \
({                                                                \
  int __ret_gu;                                                   \
  register __inttype(*(ptr)) __val_gu asm("%"_ASM_DX);            \
  __chk_user_ptr(ptr);                                            \
  might_fault();                                                  \
  asm volatile("call __get_user_%P4"                              \
               : "=a" (__ret_gu), "=r" (__val_gu),                \
                  ASM_CALL_CONSTRAINT                             \
               : "0" (ptr), "i" (sizeof(*(ptr))));                \
  (x) = (__force __typeof__(*(ptr))) __val_gu;                    \
  __builtin_expect(__ret_gu, 0);                                  \
})
```

- **核心操作**：
  - 指针有效性检查：`__chk_user_ptr(ptr)`。
  - 调用不同的子函数（如 `__get_user_1`、`__get_user_2`），根据变量大小确定。
  - 使用寄存器传递数据：
    - 输入指针 `ptr` 放入寄存器 `EAX`。
    - 用户数据读取后放入 `EDX`。
    - 结果状态码（成功或错误）放入 `EAX`。

以读取 1 字节数据为例，`__get_user_1` 的核心汇编代码如下：

```asm
.text
ENTRY(__get_user_1)
    mov PER_CPU_VAR(current_task), %_ASM_DX   // 获取当前任务描述符
    cmp TASK_addr_limit(%_ASM_DX), %_ASM_AX  // 检查用户指针是否超出用户空间
    jae bad_get_user                         // 如果超出，跳转到错误处理
    ASM_STAC                                 // 禁用 SMAP
1:  movzbl (%_ASM_AX), %edx                  // 从用户地址读取数据
    xor %eax, %eax                           // 设置成功标志
    ASM_CLAC                                 // 启用 SMAP
    ret                                      // 返回
ENDPROC(__get_user_1)

bad_get_user:
    xor %edx, %edx                           // 清零数据
    mov $(-EFAULT), %_ASM_AX                 // 设置错误码
    ASM_CLAC
    ret
END(bad_get_user)
```

- **关键步骤**：
  1. **指针验证**：检查当前指针是否在用户空间范围内。
  2. **SMAP 开关**：临时禁用 SMAP，允许内核访问用户空间。
  3. **读取数据**：通过 `movzbl` 指令从用户地址读取数据。
  4. **错误处理**：如果指针无效，则跳转到 `bad_get_user`，返回 `-EFAULT`。

### 异常处理机制

为了安全处理可能的异常（如用户指针无效），内核使用 **异常表** (`__ex_table`) 来记录访问用户空间时可能触发的故障。

每个访问用户空间的指令都有一个异常表条目，包括：
- **`from`**：故障发生的位置。
- **`to`**：错误处理代码的位置。
- **`handler`**：处理跳转逻辑的函数。

例如：

```asm
/* 定义异常表条目 */
#define _ASM_EXTABLE(from, to)                           \
  .pushsection "__ex_table","a";                         \
  .balign 4;                                             \
  .long (from) - .;                                      \
  .long (to) - .;                                        \
  .popsection
```

在发生访问故障时，内核通过异常表定位处理函数。例如：

```c
bool ex_handler_default(const struct exception_table_entry *fixup,
                        struct pt_regs *regs, int trapnr)
{
    regs->ip = ex_fixup_addr(fixup); // 设置新的返回地址
    return true;
}

int fixup_exception(struct pt_regs *regs, int trapnr)
{
    const struct exception_table_entry *e;
    ex_handler_t handler;

    e = search_exception_tables(regs->ip); // 查找异常表
    if (!e)
        return 0;

    handler = ex_fixup_handler(e);         // 获取处理函数
    return handler(e, regs, trapnr);       // 执行处理
}
```
