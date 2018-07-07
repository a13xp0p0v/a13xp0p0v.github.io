---
layout: post
title:  "Linux Kernel Defence Map"
date:   2018-04-28 13:37:00 +0300
---

## Intro

Linux kernel security is a very complex area. It would be nice to have some
graphical representation of its current state. So I've created a [__Linux Kernel
Defence Map__][1] showing the relations between:
- vulnerability classes / exploitation techniques,
- kernel defences,
- bug detection means.

__N.B.__ The node connections don't mean "full mitigation". These connections
represent some kind of relation. So ideally, this map should help to navigate
in documentation and Linux kernel sources.

I wrote it in DOT language and generated the picture using GraphViz:
```
dot -Tpng linux-kernel-defence-map.dot -o linux-kernel-defence-map.png
```
So it is very pleasant to maintain this map with git.

If you see any mistakes, feel free to create an Issue or ping me via alex.popov@linux.com

## The Map for the recent Linux Kernel

![Linux Kernel Defence Map](https://raw.githubusercontent.com/a13xp0p0v/linux-kernel-defence-map/master/linux-kernel-defence-map.png)

## Links

[Grsecurity features][2]

[The State of Kernel Self Protection by Kees Cook][3]

[Linux kernel security documentation][4]

[Linux kernel mitigation checklist by Shawn C][5]

[1]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[2]: https://grsecurity.net/features.php
[3]: https://outflux.net/slides/2018/lca/kspp.pdf
[4]: https://www.kernel.org/doc/html/latest/security/self-protection.html
[5]: https://github.com/hardenedlinux/grsecurity-101-tutorials/blob/master/kernel_mitigation.md
[6]: https://raw.githubusercontent.com/a13xp0p0v/linux-kernel-defence-map/master/linux-kernel-defence-map.png
