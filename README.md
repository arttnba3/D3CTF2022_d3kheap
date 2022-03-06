# D3CTF2022 - d3kheap

## Analysis

In this problem a kernel module called `d3kheap.ko` is loaded, which only provide you with the function of **allocating** and **freeing** objects in the size of 1024. It's easy to reverse so here comes the source code:

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

Global variables have their initialized value as follow:

```c
static void *buf = NULL;
static int ref_count = 1;
```

According to the ioctl function, we can simply know that we can only allocate once. Eyery time we make a free, the `ref_count` will minus 1, and we can't release anymore when the `ref_count` become 0.

We can easily find out that the bug is the wrong initialization of `ref_count`, which causes a double free in kernel space.

## Exploit

Because of the simple check in slub\_free (just like what glibc does in fastbin, which check the first object of the freelist), we cannot make the double free simple, but to transform it into a Use After Free.

### Construct the UAF

Firstly we need to get a UAF, it's simply to make it as follow:

- allocate an object in size of 1024
- free it
- allocate it on other structures(victim)
- free it

Though the victim is still in use, **the slub allocator treat it as a free object**, therefore the UAF has been done. And the next object that the slub is going to allocate will be the victim because of LIFO on freelist.

### Use setxattr syscall to modify the free object.

Now let's thinking about how to modify a free object. I'd like to introduce a special syscall called `setxattr`. Besides its own function, we can use it to allocate almost arbitrary size of object in kernel space.

Take a look at the source code of setxattr, it calls the `setxattr()` as follow:

```
SYS_setxattr()
    path_setxattr()
        setxattr()
```

Now let's have a look in it:

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

The `value` and the `size` can be set by the usermode caller, which means that **we can allocate an object in arbitrary size and modify it**, and after that it'll be released again, which means that **we can modify the victim by setxattr again and again**

What's not perfect is that the free objects in slub connected together as a linked list, which means that we cannot control the 8 bytes at the location `kmem_cache->offset` of the object. But it also privide us another convenience(you'll see it soon).

### use msg\_msg to make a arbitrary read in kernel space

Now we have the "primitive of write", and we need to find the "primitive of read". There're a groud of syscalls for IPC:

- msgget: create a message queue
- msgsnd: send a message to specific message queue
- msgrcv: receive a message from specific message queue

When we create a message queue, an instance of `msg_queue` will be created in kernel space to represent it:

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

And when we call the `msgsnd` syscall to send a message in specific size, a `msg_msg` will be created in kernel space:

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

These two structures consist of a double-linked list in kernel space as follow:

![image.png](https://s2.loli.net/2022/02/24/wjzFeZiDUpxXVKJ.png)

If there's only a message in the queue, it looks like this:

![image.png](https://s2.loli.net/2022/02/24/sD9xtpaHrQ2uneZ.png)

The structure of `msg_msg` is as follow:

![image.png](https://s2.loli.net/2022/02/24/5IcVxRaFQtg3HCW.png)

We can allocate a `msg_msg` in size of 1024 as the victim, and use the `setxattr` syscall to modify the `m_ts` of its header, to achieve **a read out of the boundary** on the "heap" of the kernel. What's more is that the modification of `msg_msg->next` can make an **arbitrary read** in kernel space. But the original  `msgrcv` will unlink from the double-linked list, which can surely cause a kernel panic because of wrong `m_list`. Fortunately we can set the `MSG_COPY` flag while calling `msgrcv()`, which **make a copy of the message but not to unlink it**, so that we can read the victim again and again.

The process of reading out of the boundary is simple, just use the setxattr to set the `msg_msg->next` to NULL as well as the `msg_msg->m_ts` to `0x1000 - 0x30` (max size while the `next` is NULL)

But what we can get from reading out of boundary is limited, we need to make a wider search in kernel space. It's easy to know that we can get an arbitrary read in kernel space by modifing the `msg_msg->next`, but let's take a look into `copy_msg()` first: it keeps copying the data according to the `next` of `msg_msg` and `msg_msgsed`, so if it's an invalid pointer, it'll surely cause the kernel panic.

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

So we need to **use a valid address on "kernel heap" wto search** and make sure **all addresses on the "next" list if valid, and end with a NULL**. How?

Now rethinking of the slub allocator, when we call the kmalloc, it allocates pages from buddy system and divides that in to specific size, and one of them will be send back to the caller. For the size of 1024, **4 continuous pages will be allocated by slub**, divided into 16 objects.

```shell
$ sudo cat /proc/sla 
Password: 
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
# ...
kmalloc-1k          3341   3584   1024   16    4 : tunables    0    0    0 : slabdata    224    224      0
# ...
```

**If we spray many msg\_msg in size 1024, some of them will located on the continuous 4 pages**, and when we make a reading out of boundary from one of them, **we can easily get the header of other msg\_msg**, which gives us an address on the "kernel heap"

But what it points to? Let's focus on this picture again: when there's only one message in the queue, the `msg_msg->m_list` points to the `msg_queue->q_message`, and it does the same on the opposite direction.

![image.png](https://s2.loli.net/2022/02/24/sD9xtpaHrQ2uneZ.png)

If we make the `msg_msg->next` **point back to the msg_queue, we can simply read out the address of msg\_msg, and the address of the layout there is known to us**, then we can search from the address we know so that **at every time of search we can choose a NULL as the msg_msg->next->next to prevent kernel panic**, which means that we can **read through the memory continuously now**. Fortunately the `msg_queue->q_lrpid` is NULL when we hadn't called the msgrcv, so that we can point to there firstly to read the msg\_queue.

![image.png](https://s2.loli.net/2022/02/25/5fOESRbu6Zan7mU.png)

Now it comes to the process of leaking the base of the  `.text`. Though we can get many kernel address while searching through the kernel space, we still need a proper way to calculate. I choose a fucking silly way there: generate every possible address that we may hit as a dictionary, and query it while we get the kernel pointer. If it miss the query, just search again.

### construct an A->B->A freelist to hijack new structure

Now it comes to the privilege. There're two basic way to gain the privilege in kernel pwn: modify the cred or hijack the RIP. I prefer the later one.

To achieve this, we need to allocate it at somewhere else, so we need to repair the header of msg\_msg firstly and put it back into the slub. We can just use the setxattr to do it. Some of you may doubt that the connection of freelist may crash the header of msg\_msg again, but there's a feature of slub:

- Unlike how glibc work on ptmalloc2, the slub set the pointer of next free object at the location `kmem_cache->offset`

In my own test the kmem\_cache->offset is always larger than the header of msg\_msg, so we can repair it safely.

Because of the lack of protection in `slub_free()`, we can just construct an `A->B->A` freelist (just like what we do in userspace pwning of heap)

### use the pipe\_buffer to hijack RIP

Finally I choose the `pipe_buffer` to hijack the RIP. When a pipe is created, many of them will be generate, which allocate an object of size 1024 to cover them.

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

When we close the pipe, the  `pipe_buffer->pipe_buffer_operations->release`  will be trigger, so we just need to hijack its ops to somewhere on our UAF object: we can simply calculate its address by the address of the msg\_msg we just leak before. 

Finally it just comes to the normal ROP way: choose a gadget to make the stack migration and ROP. The rsi register now points to our UAF object so I choose a gadget of `push rsi ; pop rsp ; pop 4 vals ; ret` to do it.

![image.png](https://s2.loli.net/2022/02/25/daklBHtIYCs3K6q.png)

## More...

I'm so sorry that the binary file of exploit was packed unconsciously in the rootfs.cpio together, which gave you a bad experience of pwning. SORRYYYYYYYYYYY!!!🙇🏽‍♂️🙇🏽‍♂️🙇🏽‍♂️

Besides my official solution, I think the following ways are also available:

- Because the whole file system are base on the RAM, you can search through the memory to find out the flag(I don't recommend it)
- Use other struct to hijack the RIP and construct the ROP on the `pt_regs`
- Find a way to leak the slub cookie and hijack the freelist:
  - leak out the kernel base and hojack some global pointer (like `n_tty_ops`)
  - use the prctl to modify the `comm` of `current_task` and search though the memory to find out the cred, then modify it
- use 0day or some 1day that I don't know to exploit the kernel itself
