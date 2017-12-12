---
layout: post
title:  "Blocking consecutive double-free in Linux kernel"
date:   2017-09-03 13:37:00 +0300
---

On the 7-th of August I gave a talk at [SHA2017][1]. SHA stands for Still Hacking Anyway, it is a big outdoor hacker camp in Netherlands.

The [slides][2] and recording of the talk:
<iframe width="700" height="400" src="https://www.youtube.com/embed/g7Qm0NpPAz4"></iframe>

<br>
This short article describes some new aspects of the talk, which haven't been covered in this blog.

The general method of exploiting a double-free error is based on turning it into a use-after-free bug. That is usually achieved by allocating a memory region of the same size between double `free()` calls (see the diagram below). That technique is called `heap spraying`.

<br>
![diagram](/img/usual_double_free.png){:class="img-responsive"}

<br>
However, in case of `CVE-2017-2636`, which I exploited, there are 13 buffers freed straightaway. Moreover, the double freeing happens at the beginning. So the usual heap spraying described above doesn't work for that vulnerability. Nevertheless, I've managed to turn that state of the system into a use-after-free error. I abused the naive behaviour of `SLUB`, which is currently the main Linux kernel allocator.

It turned out that `SLUB` allows consecutive double freeing of the same memory region. In contrast, GNU C library allocator has a `fasttop` check against it, which introduces a relatively small performance penalty. The idea is simple: report an error on freeing a memory region if its address is similar to the last one on the allocator's freelist.

A similar check in `SLUB` would block some double-free exploits in Linux kernel (including my PoC exploit for `CVE-2017-2636`). So I modified `set_freepointer()` function in `mm/slub.c` and sent the patch to the Linux Kernel Mailing List (LKML). It provoked a [lively discussion][3] there.

The `SLUB` maintainers didn't like that this check:
  1. introduces some performance penalty for the default `SLUB` functionality;
  2. duplicates some part of already existing `slub_debug` feature;
  3. causes a kernel oops in case of a double-free error.

I replied with these arguments:
  1. `slub_debug` is not enabled in Linux distributions by default (due to the noticeable performance impact);
  2. when the allocator detects a double-free, some severe kernel error has already occurred on behalf of some process. So it might not be worth trusting that process (which might be an exploit).

Finally Kees Cook helped to negotiate adding this check behind `CONFIG_SLAB_FREELIST_HARDENED` kernel option. So currently the second version of the patch is accepted and applied to the `linux-next` branch. It should get to the Linux kernel mainline in the nearest future.

I hope that in future some popular Linux distribution will provide the kernel with the security hardening options (including `CONFIG_SLAB_FREELIST_HARDENED`) enabled by default.

## Update

This naive double-free detection [finally got][4] to Linux kernel `v4.14` as a part of `CONFIG_SLAB_FREELIST_HARDENED`. See [Kees' post][5] for more details.

[1]: https://program.sha2017.org/events/295.html
[2]: https://program.sha2017.org/system/event_attachments/attachments/000/000/111/original/a13xp0p0v_race_for_root_SHA2017.pdf
[3]: https://lkml.org/lkml/2017/7/17/646
[4]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ce6fa91b93630396ca220c33dd38ffc62686d499
[5]: https://outflux.net/blog/archives/2017/11/14/security-things-in-linux-v4-14/
