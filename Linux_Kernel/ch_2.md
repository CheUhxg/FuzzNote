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