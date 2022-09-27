# 第二章 从内核出发

## 内核源码树

|目录|描述|
|--|--|
|arch|特定体系结构的源码|
|block|块设备IO层|
|Documentation|内核源码文档|
|drives|设备驱动程序|
|firmware|某些驱动程序需要的设备固件|
|fs|VFS和各种文件系统|
|include|内核头文件|
|init|内核引导和初始化|
|ipc|进程间通信代码|
|kernel|核心子系统（如调度程序）|
|lib|通用内核函数|
|mm|内存管理子系统和VM|
|net|网络子系统|
|samples|示范代码|
|scripts|编译内核所需脚本|
|security|安全模块|
|usr|用户空间代码|
|tools|开发工具|
|virt|虚拟化基础结构|

根目录下有些文本文件。
* COPYING：内核许可证（GNU GPL v2）。
* CREDITS：内核开发者列表。
* MAINTAINERS：内核子系统和驱动维护者列表。
* Makefile：基于内核的Makefile。

## 编译内核

### 配置内核

可以在编译内核之前，对源码进行配置。
* 可以配置以CONFIG_为前缀的选项，如CONFIG_SMP。
* 配置选项用于决定哪些文件编译进入内核，也可以通过预处理命令处理代码。

内核配置有如下方式：
``` bash
make config
make menuconfig
make gconfig
make defconfig
```

配置项会被保存在内核代码根目录下的.config文件中。
* 更改配置文件之后，更新配置操作：
``` bash
make oldconfig
```

> CONFIG_IKCONFIG_PROC把压缩过的内核配置文件存在/proc/config.gz中。
> 编译新内核时，可以使用zcat将其覆盖到.config文件中。

### 编译内核

内核配置好之后，直接使用make进行编译。

make默认只衍生一个作业，因为Makefiles常会出现不正确的依赖信息。
* 对于不正确的依赖，多个作业可能发生**相互踩踏**，导致编译出错。
* 
