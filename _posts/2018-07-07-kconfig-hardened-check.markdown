---
layout: post
title:  "Kconfig hardened check for Linux Kernel"
date:   2018-07-07 13:37:00 +0300
---

# Motivation

There are plenty of Linux kernel hardening config options. A lot of them are not enabled by the major distros. We have to enable these options ourselves to make our systems more secure.

But nobody likes checking configs manually. So let the computers do their job!

I've created a [__kconfig-hardened-check.py__][1], which helps me to check the Linux kernel Kconfig option list against my hardening preferences for `x86_64`, which are based on the [KSPP recommended settings][2] and the last public [grsecurity][3] patch (options which they disable).

Please don't cry if my Python code looks like C. I'm just a kernel developer.

# Script usage

```
#./kconfig-hardened-check.py
Usage: ./kconfig-hardened-check.py [-p | -c <config_file>]
 -p, --print
	print hardening preferences
 -c <config_file>, --config=<config_file>
	check the config_file against these preferences
```

[1]: https://github.com/a13xp0p0v/kconfig-hardened-check
[2]: http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings
[3]: https://grsecurity.net/

