# D3CTF2022 - d3kheap

## Analysis

在本题中加载了一个内核模块 `d3kheap.ko`，其本身的逻辑十分简单，只提供了一个 ioctl “菜单”，**有效的功能只有分配与释放 object**，分配的大小为 1024，逆起来还是比较容易的所以这里直接放源码了

```c
long d3kheap_ioctl(struct file *__file, unsigned int cmd, unsigned long param)
{
    spin_lock(&spin);

    switch (cmd)
    {
        case OBJ_ADD:
                if (buf)
                {
                    printk(KERN_ALERT "[d3kheap:] You already had a buffer!");
                    break;
                }
                buf = kmalloc(1024, GFP_KERNEL);
                ref_count++;
                printk(KERN_INFO "[d3kheap:] Alloc done.\n");
                break;
        case OBJ_EDIT:
                printk(KERN_ALERT "[d3kheap:] Function not completed yet, because I\'m a pigeon!");
                break;
        case OBJ_SHOW:
                printk(KERN_ALERT "[d3kheap:] Function not completed yet, because I\'m a pigeon!");
                break;
        case OBJ_DEL:
                if (!buf)
                {
                    printk(KERN_ALERT "[d3kheap:] You don\'t had a buffer!");
                    break;
                }
                if (!ref_count)
                {
                    printk(KERN_ALERT "[d3kheap:] The buf already free!");
                    break;
                }
                ref_count--;
                kfree(buf);
                printk(KERN_INFO "[d3kheap:] Free done.\n");
                break;
        default:
                printk(KERN_ALERT "[d3kheap:] Invalid instructions.\n");
                break;
    }

    spin_unlock(&spin);

    return 0;
}
```

涉及到的两个全局变量初始值如下：

```c
static void *buf = NULL;
static int ref_count = 1;
```

根据 ioctl 的逻辑，当我们分配了一个 object 之后 **ioctl 的分配功能就无效了**，而每当我们进行一次释放，`ref_count` 便会减一，当其为 0 时 **ioctl 的释放功能也被无效化**

漏洞点很明显，对 `ref_count` 的错误初始化导致我们可以释放 buf 两次，由此我们便获得了一个内核空间中的 double free

## Exploit

因为在 slub\_free 中有着对 double free 的简单检查（类似于 glibc 中的 fastbin，会检查 freelist 指向的第一个 object），因此我们不能够直接进行 double free，而应该将其转化为 UAF 进行利用

### Construct the UAF

我们首先需要构造一个 UAF，我们不难想到如下利用链：

- 分配一个 1024 大小的 object
- 释放该 object
- 将其分配到别的结构体（victim）上
- 释放该 object

此时 victim 虽然还处在使用阶段，但是**在 slub 中其同时也被视为一个 free object**，我们此时便完成了 UAF 的构造，由于 slub 遵循 LIFO，因此接下来分配的第一个大小为 1024 的 object **便会是 victim**

### Use setxattr syscall to modify the free object.

接下来我们思考如何对一个 free 状态的 object 内写入数据，这里笔者要向大家介绍一个名为 setxattr 的系统调用，这是一个十分独特的系统调用，抛开其本身的功能，在 kernel 的利用当中他可以为我们提供**近乎任意大小的内核空间 object 分配**

观察 setxattr 源码，发现如下调用链：

```
SYS_setxattr()
    path_setxattr()
        setxattr()
```

在 `setxattr()` 函数中有如下逻辑：

```c
static long
setxattr(struct dentry *d, const char __user *name, const void __user *value,
     size_t size, int flags)
{
    //...
        kvalue = kvmalloc(size, GFP_KERNEL);
        if (!kvalue)
            return -ENOMEM;
        if (copy_from_user(kvalue, value, size)) {

    //,..

    kvfree(kvalue);

    return error;
}
```

这里的 value 和 size 都是由我们来指定的，即**我们可以分配任意大小的 object 并向其中写入内容**，完成写入之后该 object 又会通过 kvfree 被释放掉，因此我们便可以通过 setxattr **多次修改 victim 的内容**

不够完美的一点是，slub 中 free 的 object 连接成一个单向链表，因此我们无法控制该 object 中 `kmem_cache->offset` 偏移处的 8 字节的内容，但这个 offset 的存在**也从另一个侧面提供给了我们便利**，在接下来的利用中你会看到这一点

### use msg\_msg to make a arbitrary read in kernel space

现在我们有了「写的原语」，接下来我们要寻找「读的原语」，在 Linux kernel 中有着一组消息队列相关的系统调用：

- msgget：创建一个消息队列
- msgsnd：向指定消息队列发送消息
- msgrcv：从指定消息队列接接收消息

当我们创建一个消息队列时，在内核空间中会创建这样一个结构体，其表示一个消息队列：

```c
/* one msq_queue structure for each present queue on the system */
struct msg_queue {
	struct kern_ipc_perm q_perm;
	time64_t q_stime;		/* last msgsnd time */
	time64_t q_rtime;		/* last msgrcv time */
	time64_t q_ctime;		/* last change time */
	unsigned long q_cbytes;		/* current number of bytes on queue */
	unsigned long q_qnum;		/* number of messages in queue */
	unsigned long q_qbytes;		/* max number of bytes on queue */
	struct pid *q_lspid;		/* pid of last msgsnd */
	struct pid *q_lrpid;		/* last receive pid */

	struct list_head q_messages;
	struct list_head q_receivers;
	struct list_head q_senders;
} __randomize_layout;
```

而当我们调用 msgsnd 系统调用在指定消息队列上发送一条指定大小的 message 时，在内核空间中会创建这样一个结构体：

```c
/* one msg_msg structure for each message */
struct msg_msg {
	struct list_head m_list;
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security;
	/* the actual message follows immediately */
};
```

在内核当中这两个结构体形成一个如下结构的循环双向链表：

![image.png](https://s2.loli.net/2022/02/24/wjzFeZiDUpxXVKJ.png)

若是消息队列中只有一个消息则是这样：

![image.png](https://s2.loli.net/2022/02/24/sD9xtpaHrQ2uneZ.png)

msg\_msg 的结构如下所示：

![image.png](https://s2.loli.net/2022/02/24/5IcVxRaFQtg3HCW.png)

我们不难想到的是，我们可以分配一个大小为 1024 的 msg\_msg 结构体作为 victim，利用 setxattr 系统调用修改其 header 中的 `m_ts` 成员，**从而实现堆上的越界数据读取**，同时还能通过修改 msg\_msg->next **实现任意地址读**，但这需要对双向链表进行 unlink，因此我们需要设置 `MSG_COPY` 标志位，这样**内核会将 message 拷贝一份后再拷贝到用户空间，原双向链表中的 message 并不会被 unlink**，从而我们便可以多次重复地读取同一个 `msg_msg` 结构体中数据

接下来我们考虑越界读取的详细过程，我们首先可以利用 setxattr 修改 msg\_msg 的 `next` 指针为 NULL、将其 `m_ts` 改为 `0x1000 - 0x30`（在 next 指针为 NULL 的情况下，一个 msg\_msg 结构体最大占用一张内存页的大小），从而越界读出内核堆上数据

但仅仅是越界读出一张内存页的数据往往不能够让我们泄露出所需的数据，因此接下来我们思考如何进行“合法”的搜索。我们不难想到的是我们可以通过修改 `next` 指针来完成**任意地址读**，但在此之前我们先来看 `copy_msg` 的逻辑，其拷贝时判断待数据长度的逻辑**主要是看 next 指针**，因此若我们的 next 指针为一个非法地址，则会在解引用时导致 kernel panic

```c
struct msg_msg *copy_msg(struct msg_msg *src, struct msg_msg *dst)
{
	struct msg_msgseg *dst_pseg, *src_pseg;
	size_t len = src->m_ts;
	size_t alen;

	if (src->m_ts > dst->m_ts)
		return ERR_PTR(-EINVAL);

	alen = min(len, DATALEN_MSG);
	memcpy(dst + 1, src + 1, alen);

	for (dst_pseg = dst->next, src_pseg = src->next;
	     src_pseg != NULL;
	     dst_pseg = dst_pseg->next, src_pseg = src_pseg->next) {

		len -= alen;
		alen = min(len, DATALEN_SEG);
		memcpy(dst_pseg + 1, src_pseg + 1, alen);
	}

	dst->m_type = src->m_type;
	dst->m_ts = src->m_ts;

	return dst;
}
```

因此我们需要确保**获得一个合法的堆上地址进行搜索的同时**确保我们所构造的**next 链上皆为合法地址，并以 NULL 结尾**，如何找到这样一个地址？

我们都知道，slub 会向 buddy system 申请一张或多张连续内存页，将其分割为指定大小的 object 之后再返还给 kmalloc 的 caller，对于大小为 1024 的 object，其每次申请的连续内存页为四张，分为 16 个 object

```shell
$ sudo cat /proc/sla 
Password: 
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
# ...
kmalloc-1k          3341   3584   1024   16    4 : tunables    0    0    0 : slabdata    224    224      0
# ...
```

我们不难想到的是，若是我们**分配多个大小同为 1024 的 msg\_msg 结构体，则其很容易落在地址连续的 4 张内存页上**，此时若是我们从其中一个 msg\_msg 结构体向后进行越界读，**则很容易读取到其他的 msg\_msg 结构体的数据**，其 m\_list 成员可以帮助我们泄露出一个堆上地址

那么这个堆上地址指向哪呢？让我们将目光重新放回 `msg_queue` 与 `msg_msg` 结构体之间的关系，当一个消息上只有一个 message 时，我们不难看出 msg\_msg 的 prev 与 next 指针都指向 msg\_queue 的 `q_messages` 域，对应地， msg\_queue->q\_message 的 prev 与 next 也同样指向 msg\_msg 的 `m_list` 域

![image.png](https://s2.loli.net/2022/02/24/sD9xtpaHrQ2uneZ.png)

此时我们不难想到，**我们可以将 msg\_msg 的 next 指针指回 msg\_queue，从而读出上面的指向 msg\_msg 的指针，将未知的地址变为已知的地址**，之后我们在搜索时便可以选择从该地址开始搜索，这样我们就能知道每次搜索时获得的每一条数据的地址，**从而在每次搜索时能够挑选已知数据为 NULL 的区域作为 next->next 以避免 kernel panic**，以此获得连续的搜索内存的能力。幸运的是，在我们未调用 msgrcv 时 `msg_queue->q_lrpid` 为 NULL，因此一开始我们可以将 next 指针指向该位置 

![image.png](https://s2.loli.net/2022/02/25/5fOESRbu6Zan7mU.png)

泄露出 msg\_msg 的地址之后就可以开始愉快的内存搜索了，至于在泄露出内核代码段上指针后如何计算出内核代码段基址，笔者这里的做法比较笨：将经常出现的内核指针做成一个字典，之后直接 query 即可，若字典未命中则继续搜索

### construct an A->B->A freelist to hijack new structure

现在地址泄露的工作已经完成了，接下来我们来考虑如何进行提权，比较朴素的提权方法有两种：修改进程 cred 结构体或是劫持内核执行流，在这里笔者选择劫持内核执行流。

我们需要将该 UAF object 分配到别的地方，因此接下来我们的工作便是先维修 msg\_msg 中的双向链表，将其重新放回 slub 中，只需要让其 m\_list 指向内核堆上一个合法的地址，同时让 next 指针为 NULL 即可，这里我们可以直接选择使用 setxattr 完成修复，可能有的同学这里会有疑问：m\_list 成员位于 msg\_msg 的前 16 字节，在 setxattr 将其放回 slub 时**难道不会又将其修改为一个 slub 中的指针从而破坏双向链表么**？开启了 hardened freelist 保护时 free object 的 next 指针字面量并非一个合法地址。这里我们就要说到 slub 的一个特性了：

- 不同于 glibc 中空闲堆块固定使用前 8 字节的组织方式，在 slub 中空闲的 object 在其对应的 kmem\_cache->offset 处存放下一个 free object 的指针（开启了 hardened freelist 保护时该值为当前 object 与 下一个 object 地址再与一个 random 值总共三个值进行异或的结果）

经笔者多次测试，对于这种较大的 object 而言，其 offset 通常会大于 msg\_msg header 的大小，因此我们可以进行完美修复

修复完成之后我们考虑如何进行 double free，因为 slub 的释放函数并没有太多的保护，如同 glibc 中的 fastbin 一般只会检查 freelist 上的第一个 object，因此我们只需要像做用户态 pwn 题那样构造 A->B->A 的释放链便能将 UAF 再应用到其他内核结构体上

### use the pipe\_buffer to hijack RIP

最后我们来挑选一个内核结构体来劫持 RIP，这里笔者选择了 `pipe_buffer` 这一结构体，当我们创建一个管道时，在内核中会生成数个连续的该结构体，申请的内存总大小刚好会让内核从 kmalloc-1k 中取出一个 object

```c
/**
 *	struct pipe_buffer - a linux kernel pipe buffer
 *	@page: the page containing the data for the pipe buffer
 *	@offset: offset of data inside the @page
 *	@len: length of data inside the @page
 *	@ops: operations associated with this buffer. See @pipe_buf_operations.
 *	@flags: pipe buffer flags. See above.
 *	@private: private data owned by the ops.
 **/
struct pipe_buffer {
	struct page *page;
	unsigned int offset, len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	unsigned long private;
};
```

而当我们关闭了管道的两端时，会触发 `pipe_buffer->pipe_buffer_operations->release` 这一指针，因此我们只需要劫持其函数表即可，劫持的位置也很清晰：前面我们在搜索内存时获取到了其中一个 msg\_msg 的地址，只需要减去其与被用于 UAF 的 object 的地址之间的偏移即可，这个偏移值在搜索过程中是可以计算出来的

之后我们将函数表劫持到 pipe\_buffer 所处 object 上，在该 object 上布置好 ROP 链，再选一条合适的用于栈迁移的 gadget 即可。经笔者实测，此时的 rsi 寄存器指向 pipe\_buffer，因此笔者选择了一条 `push rsi ; pop rsp ; pop 4 vals ; ret` 的 gadget 完成栈迁移

![image.png](https://s2.loli.net/2022/02/25/daklBHtIYCs3K6q.png)

## More...

非常抱歉在本次比赛当中笔者将 exp 给打包进了 rootfs 的 `/tmp` 目录下忘记删除，给各位大师傅们带来了十分不好的做题体验，在这里献上笔者最诚挚的歉意🙇🏽‍♂️🙇🏽‍♂️🙇🏽‍♂️

除了笔者的官方解法以外，笔者认为以下方法应当也能解开本题（笔者未进行尝试）：

- 由于整个文件系统是直接在内存中的，因此可以直接搜索内存寻找 flag（笔者本人并不推荐这种专注于 flag 本身的解法）
- 直接分配其他可以劫持 RIP 的结构体，然后爆破内核 .text 段偏移，在 pt\_regs 上构造 ROP
- slub 大师通过巧妙构造泄露出 cookie 与堆上地址，然后劫持 freelist（笔者有思路但笔者认为这种解法过于麻烦 + 没有必要）
  - 泄露出内核基址后后写一些全局指针（例如 `n_tty_ops`）
  - 利用 prctl 修改 current\_task 的 comm 成员，暴力搜索内存找到 cred
- 利用 0day 或是（笔者不知道的） 1day 直接打 kernel
