# 目的

实现在open函数的实现中，添加调试信息并触发UAF漏洞。

# 步骤

尝试了很多个接口，最终在do_sys_open()函数实现了调试信息的插入。

``` c
long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode)
{
    if(strcmp(filename, "/tmp/null") == 0) {
        printk("do_sys_open: filename == /tmp/null\n");
        char *p = (char *)kmalloc(8, GFP_USER);
        kfree(p);
        *p = 'a';
    }
    ...
}
```

根据上述插入代码，我们只需要在用户空间调用open函数打开`/tmp/null`文件就可以触发UAF漏洞了。
