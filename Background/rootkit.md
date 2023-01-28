## 知识点

* Linux-2.4高速缓存**由slab分配器以链表的形式**管理。
  * 每个高速缓存被划分为若干个slab。
    * 高速缓存用kmem_cache_s结构来表示。
  * 每个slab里可分配多个对象。
    * 每个slab用slab_s结构表示。

* Linux-2.6在2.4基础上新增了为每个cpu分配的array_cache结构*arry*和所有cpu共用的array_cache结构*share*。
  * 分配内存顺序：array->list->BuddySystem。（TODO:为什么要从array中分配？）

* Linux-2.4上的task_struct是直接**以内存页为单位分配**的，基于以下*三个特征*，可以判断内存页低内存区域是否是task_struct。
  1. task_struct的成员变量pid其取值只能属于\[0,MAX_PID\]区间；
  2. task_struct的成员变量comm的长度小等于16；
  3. task_struct的成员变量user所指向的用户信息中的用户标识符应与task_struct的成员变量uid一致。

* Linux-2.6在2.4的基础上，使用成员变量tasks将所有task_struct组织在一个双向链表中，并且task_struct由专用高速缓存分配。
  * 由于Linux-2.6有array和share缓存，在遍历对象时，需判断其释放是否是回到slab。

