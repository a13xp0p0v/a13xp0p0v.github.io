---
layout: post
title:  "So near and yet so far: Cross compiler debugging war-story"
date:   2020-05-26 13:37:00 +0300
---

That is a short funny article that I decided to write after two days (and nights) of amazingly painful and hilarious debugging of a cross compiler.

## Intro

Two years ago I was working on [porting STACKLEAK security feature][0] from Grsecurity/PaX into the Linux kernel mainline. The feature [has landed][1] in `v4.20`, but without detecting Stack Clash attack [against Linux kernel][2]. That functionality was not needed because during discussion of the patch series, the maintainers decided to remove all Variable Length Arrays (VLA) from the mainline kernel. Kees Cook with a team of kernel developers participated in that big cleanup. Now it is finished and the kernel is built with `-Wvla`, so `alloca()` is prohibited in the kernel, which is nice.

Currently I'm working on a patch series that improves the STACKLEAK gcc plugin in the mainline. Among other things, I've made the stack tracking instrumentation simpler, dropped searching for `alloca()` and added this assertion:

```c
	/* Variable Length Arrays (VLAs) are forbidden in the kernel */
	gcc_assert(!cfun->calls_alloca);
```

Testing gcc plugins for Linux kernel is a big headache, since the kernel can be built with any gcc version [starting from gcc-4.6][3]! That is why I've created the [kernel-build-containers][4] project that provides Docker containers for handy building of Linux kernel (or other software) with various compilers for various architectures.

Last Friday evening I started the final testing of my STACKLEAK improvements and launched kernel compilation in `kernel-build-containers`. But next morning I was really confused by the results:
<br/>

|     | gcc-4.8 | gcc-5 | gcc-6 | gcc-7 | gcc-8 | gcc-9 | gcc-10|
|:---:|:-------:|:-----:|:-----:|:-----:|:-----:|:-----:|:-----:|
| __build for `x86_64`__ |<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|
| __cross build for `arm64`__ |gcc plugins not supported|<span style="color:red">assertion failed</span>|<span style="color:red">assertion failed</span>|<span style="color:green">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OK&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>|<span style="color:green">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OK&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>|<span style="color:green">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OK&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>|<span style="color:green">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OK&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>|
| __cross build for `i386`__ |<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|<span style="color:green">OK</span>|

<p align="center">
  <img width="560" src="/img/puzzled.jpg">
  <br/>
  <a href="https://www.flickr.com/photos/philipdunn/3041924216">img src</a>
</p>
<br/>

## Looks easy!

So my assertion failed for gcc before version 7 only for `arm64`. At first I thought: "Not a big problem! I know what to do: simply debug the compiler using gdb. I did it several times before. Easy!"

<p align="center">
  <img width="560" src="/img/mememe_hold_my_beer.jpg">
</p>
<br/>

Okay. Sunday night... So quiet around (kids are sleeping)... Time to get some drink and build a compiler with debug symbols and then quickly find the issue in the morning. Huh, not so easy. And the painful fun began.

I needed a cross compiler that builds the kernel for `arm64` on my `x86_64` machine. There are many nice tutorials about creating it, for example [this][5] and [this][6] and [that][7]. I struggled with them for several hours, but failed. Making `libgcc` was missing various headers all the time. Finally a nice idea crossed my tired mind: __give up and just install debug symbols for the cross compiler package in the build container, so easy!__ Nice, I went to sleep satisfied with that.

## Give me debug symbols!

On Monday morning I started an interactive shell in the container, going to install debug symbols for `gcc-6-aarch64-linux-gnu`:

```console
$ sh run_container.sh gcc-6 ~/linux/linux/ ~/linux/build_out/ 
Hey, we gonna use sudo for running docker
Starting "kernel-build-container:gcc-6"
Source code directory "/home/a13x/linux/linux/" is mounted at "~/src"
Build output directory "/home/a13x/linux/build_out/" is mounted at "~/out"
Gonna run interactive bash...
```

The `kernel-build-containers` are based on Ubuntu, so I followed the how-to in [Ubuntu Debug Symbol Packages][8] documentation...

__Fail! No luck!__ Ubuntu doesn't provide `gcc-6-aarch64-linux-gnu-dbgsym` package. There is no debug symbol package for __any__ gcc cross compiler for `aarch64` at [http://ddebs.ubuntu.com][9]. Grrr, not funny. I decided to try the same on Fedora. But how to install old `gcc-6` on my relatively fresh `Fedora 31`? Oh, that is pain. You need to search for the desired package and its dependencies at some RPM search engines, download them... No!

<p align="center">
  <img width="560" src="/img/mememe_give_me_debug_symbols.jpg">
</p>
<br/>

So I wrote a Docker file with ancient `Fedora 24` that goes with `gcc-6` out of the box:

```bash
FROM fedora:24 as base

RUN dnf -y update && \
  dnf -y install gcc gcc-c++ gcc-aarch64-linux-gnu gcc-c++-aarch64-linux-gnu gcc-plugin-devel \
    gcc-gdb-plugin libgcc sudo flex bison make git ctags ncurses-devel openssl-devel

ARG UNAME
ARG UID
ARG GID
RUN groupadd -g ${GID} -o ${UNAME} && \
    useradd -u $UID -g $GID -ms /bin/bash ${UNAME} && \
    echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

USER ${UNAME}
WORKDIR /home/${UNAME}/src

CMD ["bash"]
```

Yeah, the container worked. Now getting debug symbols for a package should be easy as:
```console
$dnf debuginfo-install gcc-aarch64-linux-gnu
```

What?! __It failed!__ Fedora doesn't provide the debuginfo for the cross compiler, it has only `gcc-base-debuginfo` for regular `gcc-6`. So near and yet so far :(


## Building cross compiler: second try

Back in 2012 I was an embedded kernel developer. These good old days still remind me that __toolchains are complicated__. So I decided not to try building the cross compiler myself again, but use the knowledge of real experts in that area. From Open Source Summit I remembered that [Thomas Petazzoni][10] at Bootlin told that `the Buildroot project` can create a toolchain in addition to the kernel and file system of an embedded device. So I found the [buildroot-toolchains][11] project, cloned and started to learn it.

The configuring looked quite straightforward. Buildroot uses `kconfig`, just like the Linux kernel. So I took a [Buildroot config fragment][12] from a similar toolchain and changed these options:

```
BR2_ENABLE_DEBUG=y
BR2_DEBUG_2=y
# BR2_STRIP_strip is not set
BR2_OPTIMIZE_G=y
BR2_GCC_VERSION_6_X=y
BR2_GCC_VERSION="6.4.0"
```

Then I invoked `make`, but building failed with error. Oh! It turned out that default `master` branch of `buildroot-toolchains` repository is [out-of-date][13]. On the other hand the fresh `toolchains.bootlin.com-2020.02` branch doesn't support old `gcc-6`. Finally I determined that `stable` branch both works and supports `gcc-6`. It built the toolchain! But gcc was built without debug symbols. But why `BR2_ENABLE_DEBUG` didn't work?

I found that `BR2_ENABLE_DEBUG` config option is only about __target__ Buildroot packages. But toolchain is a __host__ package. So I hacked the Makefile a bit and got the cross compiler with debug symbols:

```diff
diff --git a/package/gcc/gcc-final/gcc-final.mk b/package/gcc/gcc-final/gcc-final.mk
index dfad3d3110..76a9dd8bbf 100644
--- a/package/gcc/gcc-final/gcc-final.mk
+++ b/package/gcc/gcc-final/gcc-final.mk
@@ -42,7 +42,7 @@ HOST_GCC_FINAL_PRE_CONFIGURE_HOOKS += HOST_GCC_CONFIGURE_SYMLINK
 define  HOST_GCC_FINAL_CONFIGURE_CMDS
        (cd $(HOST_GCC_FINAL_SRCDIR) && rm -rf config.cache; \
                $(HOST_CONFIGURE_OPTS) \
-               CFLAGS="$(HOST_CFLAGS)" \
+               CFLAGS="$(HOST_CFLAGS) -g3 -O0" \
                LDFLAGS="$(HOST_LDFLAGS)" \
                $(HOST_GCC_FINAL_CONF_ENV) \
                ./configure \
```

The main achievement: Buildroot produced `aarch64-buildroot-linux-gnu-gcc` and `aarch64-buildroot-linux-gnu-g++` with gcc plugin support, which I really needed. I was sitting at the kitchen on late Monday night and laughing happily :)

## GCC & GDB: practical example

I added this new toolchain to `$PATH` and tried to cross-compile the kernel with STACKLEAK improvements:

```console
$ make ARCH=arm64 CROSS_COMPILE=aarch64-buildroot-linux-gnu-
```

The assertion failed again, the bug was reproduced:

```
*** WARNING *** there are active plugins, do not report this as a bug unless you can reproduce it without enabling any plugins.
Event                            | Plugins
PLUGIN_START_UNIT                | stackleak_plugin
arch/arm64/kernel/perf_event.c: In function ‘armv8pmu_handle_irq’:
arch/arm64/kernel/perf_event.c:728:1: internal compiler error: in stackleak_cleanup_execute, at scripts/gcc-plugins/stackleak_plugin.c:390
 }
 ^
0x7fffea99a819 stackleak_cleanup_execute
	scripts/gcc-plugins/stackleak_plugin.c:390
0x7fffea99a819 execute
	scripts/gcc-plugins/gcc-generate-rtl-pass.h:127
```

From then I knew what to do. First, I rebuilt the kernel with `V=1` argument. It allowed to show the gcc invocation command that failed:

```
aarch64-buildroot-linux-gnu-gcc -Wp,-MD,arch/arm64/kernel/.perf_event.o.d  -nostdinc -isystem /home/a13x/Develop_local/linux/build_out/toolchain/bin/../lib/gcc/aarch64-buildroot-linux-gnu/6.4.0/include -I./arch/arm64/include -I./arch/arm64/include/generated  -I./include -I./arch/arm64/include/uapi -I./arch/arm64/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -include ./include/linux/compiler_types.h -D__KERNEL__ -mlittle-endian -DKASAN_SHADOW_SCALE_SHIFT=3 -Wall -Wundef -Werror=strict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE -Werror=implicit-function-declaration -Werror=implicit-int -Wno-format-security -std=gnu89 -mgeneral-regs-only -fno-asynchronous-unwind-tables -Wno-psabi -mabi=lp64 -DKASAN_SHADOW_SCALE_SHIFT=3 -fno-delete-null-pointer-checks -Wno-frame-address -O2 --param=allow-store-data-races=0 -fplugin=./scripts/gcc-plugins/stackleak_plugin.so -DSTACKLEAK_PLUGIN -fplugin-arg-stackleak_plugin-track-min-size=100 -fplugin-arg-stackleak_plugin-arch=arm64 -fplugin-arg-stackleak_plugin-verbose -Wframe-larger-than=2048 -fstack-protector-strong -Wno-unused-but-set-variable -Wno-unused-const-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -fno-var-tracking-assignments -g -Wdeclaration-after-statement -Wvla -Wno-pointer-sign -Wno-array-bounds -Wno-maybe-uninitialized -fno-strict-overflow -fno-merge-all-constants -fmerge-constants -fno-stack-check -fconserve-stack -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init    -DKBUILD_MODFILE='"arch/arm64/kernel/perf_event"' -DKBUILD_BASENAME='"perf_event"' -DKBUILD_MODNAME='"perf_event"' -c -o arch/arm64/kernel/perf_event.o arch/arm64/kernel/perf_event.c
```

In fact `aarch64-buildroot-linux-gnu-gcc` is not a compiler itself, that is only a wrapper. Hence for debugging with gdb we need a special trick: adding `-wrapper gdb,--args` at the end of this command. Here is my debugging session:

 1. GDB says that debug symbols are found:
  ```
  GNU gdb (GDB) Fedora 8.3.50.20190824-30.fc31
  ...
  Reading symbols from libexec/gcc/aarch64-buildroot-linux-gnu/6.4.0/cc1...
  ```

 2. Request the breakpoint near my gcc pass:
  ```
  (gdb) break execute_fixup_cfg()
  Breakpoint 1 at 0x9882c0
  ```

 3. Run the compiler
  ```
  (gdb) run 
  Breakpoint 1, 0x00000000009882c0 in execute_fixup_cfg() ()
  ```

 4. Which source code function is currently compiled?
  ```
  (gdb) p current_function_decl->decl_minimal.name->identifier.id.str
  $11 = (const unsigned char *) 0x7fffe9b7d3b0 "get_irq_regs"
  ```

 5. Set the watchpoint for the action that will later break the assertion:
  ```
  (gdb) watch -l ((struct function *)cfun)->calls_alloca
  Hardware watchpoint 2: -location ((struct function *)cfun)->calls_alloca
  ```

 6. Show the breakpoints, delete the unneeded one and continue:
  ```
  (gdb) info breakpoints 
  Num     Type           Disp Enb Address  What
  1       breakpoint     keep y   0x00000000009882c0 <execute_fixup_cfg()>
  	breakpoint already hit 21 times
  2       hw watchpoint  keep y            -location ((struct function *)cfun)->calls_alloca
  (gdb) delete breakpoints 1
  (gdb) c
  Continuing.
  ```

 7. Get the bug!
  ```
  Hardware watchpoint 3: -location ((struct function *)cfun)->calls_alloca
  Old value = 0
  New value = 1
  0x00000000006cad6f in allocate_dynamic_stack_space(rtx_def*, unsigned int, unsigned int, bool) ()
  (gdb) p current_function_decl->decl_minimal.name->identifier.id.str
  $81 = (const unsigned char *) 0x7fffe7456d98 "armv8pmu_handle_irq"
  (gdb) bt
  #0  0x00000000006cad6f in allocate_dynamic_stack_space(rtx_def*, unsigned int, unsigned int, bool) ()
  #1  0x0000000000603a84 in expand_stack_vars(bool (*)(unsigned long), stack_vars_data*) ()
  #2  0x000000000060e235 in expand_used_vars() ()
  #3  0x000000000060fbf4 in (anonymous namespace)::pass_expand::execute(function*) ()
  #4  0x00000000008ac0c2 in execute_one_pass(opt_pass*) ()
  #5  0x00000000008ac668 in execute_pass_list_1(opt_pass*) ()
  #6  0x00000000008ac6c9 in execute_pass_list(function*, opt_pass*) ()
  #7  0x0000000000639a1f in cgraph_node::expand() ()
  #8  0x000000000063af45 in symbol_table::compile() [clone .part.0] ()
  #9  0x000000000063c96b in symbol_table::finalize_compilation_unit() ()
  #10 0x0000000000958651 in compile_file() ()
  #11 0x0000000000520b29 in toplev::main(int, char**) ()
  #12 0x0000000000522a60 in main ()
  ```

Here `expand_stack_vars()` calls `allocate_dynamic_stack_space()` that sets `cfun->calls_alloca` for functions that in fact don't call `alloca()`. I searched in gcc repository history for changes in `expand_stack_vars()` implementation and found the commit fixing that strange behaviour in `gcc-7`:

```
commit 7072df0aae0c59ae437e5cc28e4e5e5777e930ba
Author: Dominik Vogt <vogt@linux.vnet.ibm.com>
Date:   Mon Jul 18 13:10:27 2016 +0000

    Allocate constant size dynamic stack space in the prologue
    
    The attached patch fixes a warning during Linux kernel compilation
    on S/390 due to -mwarn-dynamicstack and runtime alignment of stack
    variables with constant size causing cfun->calls_alloca to be set
    (even if alloca is not used at all).  The patched code places
    constant size runtime aligned variables in the "virtual stack
    vars" area instead of creating a "virtual stack dynamic" area.
    
    This behaviour is activated by defining
    
      #define ALLOCATE_DYNAMIC_STACK_SPACE_IN_PROLOGUE 1
```

Ha-ha! It was fixing another warning during Linux kernel compilation back in 2016. That it funny.

## Conclusion

In Russia we have an idiom `"близок локоток, да не укусишь"` that can be translated like `"your elbow is near, but you can't bite it, dear"`. That debugging was painful, thanks God, I managed to make this "bite". Writing this article helped me to relax. Hope you enjoyed reading!

[0]: https://a13xp0p0v.github.io/2018/11/04/stackleak.html
[1]: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=10e9ae9fabaf96c8e5227c1cd4827d58b3aa406d
[2]: https://grsecurity.net/an_ancient_kernel_hole_is_not_closed
[3]: https://www.kernel.org/doc/html/latest/process/changes.html
[4]: https://github.com/a13xp0p0v/kernel-build-containers
[5]: https://preshing.com/20141119/how-to-build-a-gcc-cross-compiler/
[6]: https://docs.slackware.com/howtos:hardware:arm:gcc-9.x_aarch64_cross-compiler
[7]: https://wiki.osdev.org/GCC_Cross-Compiler
[8]: https://wiki.ubuntu.com/Debug%20Symbol%20Packages
[9]: http://ddebs.ubuntu.com
[10]: https://github.com/tpetazzoni
[11]: https://github.com/bootlin/buildroot-toolchains
[12]: https://toolchains.bootlin.com/downloads/releases/toolchains/aarch64/build_fragments/aarch64--glibc--bleeding-edge-2018.11-1.defconfig
[13]: https://github.com/bootlin/buildroot-toolchains/branches

