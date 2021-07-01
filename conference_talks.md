---
layout: page
title: "Conference Talks"
permalink: /conference_talks/
---

# [Сила четырех байтов: эксплуатация уязвимости CVE-2021-26708 в ядре Linux][38]

__Conference:__ Positive Hack Days 10

__Date:__ 20.05.2021

[__Slides__][39] &nbsp; &nbsp; [__Video__][40]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/ZB-VYx3578s" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

В январе 2021 года Александр обнаружил и устранил пять уязвимостей в реализации виртуальных сокетов ядра Linux. Этим уязвимостям был присвоен идентификатор [CVE-2021-26708][35]. Докладчик детально расскажет об эксплуатации одной них для локального повышения привилегий на Fedora 33 Server для платформы x86_64. Исследователь продемонстрирует, как с помощью небольшой ошибки доступа к памяти получить контроль над всей операционной системой и при этом обойти средства обеспечения безопасности платформы.

<br/>

# [Four Bytes of Power: Exploiting CVE-2021-26708 in the Linux Kernel][33]

__Conference:__ Zer0Con 2021

__Date:__ 09.04.2021

[__Slides__][34] &nbsp; &nbsp; [__Video__][37]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/EMcjHfceX44" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

[CVE-2021-26708][35] is assigned to five race condition bugs in the virtual socket implementation of the Linux kernel. These vulnerabilities were [discovered and fixed][36] by Alexander Popov. In this talk, he will describe how to exploit them for local privilege escalation on Fedora 33 Server for x86_64, bypassing SMEP and SMAP. Alexander will demonstrate an artful way of turning very limited kernel memory corruption into a powerful weapon.

<br/>

# [Following the Linux Kernel Defence Map][28]

__Conference:__ Linux Plumbers Conference 2020

__Date:__ 25.08.2020

[__Slides__][29] &nbsp; &nbsp; [__Video__][30]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/4c01jjbQmBc?start=8555" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />
__Description__

Linux kernel security is a very complex topic. To learn it, I created a [Linux Kernel Defence Map][31] showing the relationships between vulnerability classes, exploitation techniques, bug detection mechanisms, defence technologies.

These kernel defence technologies have the corresponding Kconfig options. A lot of them are not enabled by the major Linux distributions. So I created a [kconfig-hardened-check][32] tool that can help to examine security-related options in your Linux kernel config.

In this short talk we will follow the [Linux Kernel Defence Map][31] and explore the [kconfig-hardened-check][32] tool.

<br/>

# [Panel Discussion: What is Lacking in Linux Security and What Are or Should We be Doing about This][26]

__Conference:__ Linux Security Summit North America 2020

__Date:__ 01.07.2020

[__Video__][27]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/v7_mwg5f2cE?start=70" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Participants:__ Elena Reshetova (Intel), Allison Marie Naaktgeboren (PhD Student), Alexander Popov (Positive Technologies), Mimi Zohar (IBM), Kees Cook (Google)

<br/>

# [Exploiting a Linux Kernel Vulnerability in the V4L2 Subsystem][23]

__Conference:__ OffensiveCon 2020

__Date:__ 15.02.2020

[__Slides__][24] &nbsp; &nbsp; [__Video__][25]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/J6xIohyARSU" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

CVE-2019-18683 refers to a bunch of 5-year old race conditions in the V4L2 subsystem of the Linux kernel which were fixed by Alexander Popov at the end of 2019. In this talk he will describe the PoC exploit of these issues for x86_64. Alexander will explain the effective method of hitting the race condition and show how to gain local privilege escalation from the kernel thread context bypassing SMEP and SMAP on Ubuntu Server 18.04.

<br/>

# [Фаззинг ядра Linux на практике][20]

__Conference:__ ISPRAS Open Conference 2019

__Date:__ 06.12.2019

[__Slides__][21] &nbsp; &nbsp; [__Video__][22]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/pt9rlhFMRmc" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

В своем докладе Александр Попов даст краткий обзор техники фаззинга (fuzzing) и устройства фаззера syzkaller. Затем
он поделится своим практическим опытом поиска уязвимостей в ядре Linux с помощью данного инструмента и расскажет о
том, что препятствует эффективному фаззингу.

<br/>

# [Между двух огней: уроки участия в Kernel Self Protection Project][17]

__Conference:__ Linux Piter 2018

__Date:__ 03.11.2018

[__Slides__][18] &nbsp; &nbsp; [__Video__][19]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/LeKBVgTE6YY" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Безопасность - непростая тема для сообщества разработчиков ядра Linux. Внедрение новых средств безопасности в ванильное ядро обычно вызывает горячие дискуссии в списках рассылки и даже социальных сетях. Разработчики из Grsecurity/PaX, Kernel Self Protection Project (KSPP), мэйнтейнеры ядра и Линус Торвальдс - все имеют различные мнения.

Александр Попов вышел на это "поле боя" весной 2017 года и с тех пор участвует в Kernel Self Protection Project. Этот путь оказался намного сложнее, чем он ожидал. В своем докладе Александр поделится уроками разработки средств безопасности в сообществе ядра Linux.

<br/>

# [Between the Millstones: Lessons of Self-Funded Participation in Kernel Self Protection Project][15]

__Conference:__ Open Source Summit Europe 2018

__Date:__ 22.10.2018

[__Slides__][16]

__Description__

Security is not an easy topic for the Linux kernel community. Upstreaming security features usually provokes hot discussions in the Linux Kernel Mailing List and in social networks. Grsecurity/PaX, Kernel Self Protection Project (KSPP), kernel maintainers and Linus all have different opinions.

Alexander Popov entered this battlefield in spring 2017 and started his self-funded participation in KSPP. This way turned out to be much more complicated than he had predicted. In this talk Alexander will share his experience and lessons learnt during mainlining Linux kernel security features.

<br/>

# [STACKLEAK: A Long Way to the Linux Kernel Mainline][12]

__Conference:__ Linux Security Summit North America 2018

__Date:__ 27.08.2018

[__Slides__][13] &nbsp; &nbsp; [__Video__][14]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/5wIniiWSgUc" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

STACKLEAK is a Linux kernel security feature initially created by Grsecurity/PaX developers. In May of 2017 Alexander Popov took on the task of introducing STACKLEAK into the Linux kernel mainline. The way to the mainline turned out to be long and complicated.

<br/>

# [How STACKLEAK improves Linux kernel security][9]

__Conference:__ Linux Piter 2017

__Date:__ 04.11.2017

[__Slides__][10] &nbsp; &nbsp; [__Video__][11]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/oF8K9-8fXMQ" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

STACKLEAK is a Linux kernel security feature initially created by Grsecurity/PaX developers. Alexander Popov took on the task of introducing STACKLEAK into the Linux kernel mainline. In this talk Alexander describes the inner workings of this security feature and why the vanilla kernel needs it. In fact, STACKLEAK mitigates several types of Linux kernel vulnerabilities due to:
 - reducing the information that can be revealed through kernel stack leak bugs;
 - blocking some uninitialized stack variable attacks;
 - introducing some runtime checks for kernel stack overflow detection.

<br/>

# [Race For Root: The Analysis Of The Linux Kernel Race Condition Exploit][6]

__Conference:__ Still Hacking Anyway (SHA2017)

__Date:__ 07.08.2017

[__Slides__][7] &nbsp; &nbsp; [__Video__][8]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/g7Qm0NpPAz4" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

CVE-2017-2636 is a 7-year old race condition in the Linux kernel that was fixed by Alexander Popov in March, 2017. This vulnerability affected all major Linux distributions. It can be exploited to gain a local privilege escalation. In this presentation Alexander will describe the PoC exploit for CVE-2017-2636. He will explain the effective method of hitting the race condition and show the following exploitation techniques: turning double-free into use-after-free, heap spraying and stabilization, SMEP bypass.

<br/>

# [KASan in Bare-Metal Hypervisor][4]

__Conference:__ LinuxCon Japan 2016

__Date:__ 13.07.2016

[__Slides__][5]

__Description__

Kernel address sanitizer (KASan) is a dynamic memory error detector for finding out-of-bounds and use-after-free bugs in Linux kernel. It uses shadow memory to record whether each byte of memory is safe to access and uses compile-time instrumentation to check shadow memory
on each memory access. In this presentation Alexander Popov will describe the successful experience of porting KASan to a bare-metal hypervisor: the main steps, pitfalls and the ways to make KASan checks much more strict and multi-purpose.

<br/>

# [Использование KASan для автономного гипервизора][1]

__Conference:__ Positive Hack Days VI

__Date:__ 17.05.2016

[__Slides__][2] &nbsp; &nbsp;

__Description__

В настоящем докладе будет рассмотрен успешный опыт использования отладочного механизма KASan (Kernel address sanitizer) для автономного гипервизора. Докладчик расскажет, как удалось усилить KASan по сравнению с его реализацией в ядре Linux.

[1]: http://2016.phdays.ru/program/49625/
[2]: /img/Alexander_Popov-KASan_in_a_Bare-Metal_Hypervisor-PHDays_VI.pdf

[3]: https://www.youtube.com/watch?v=5db2ULz6ikw
[4]: https://lcccjapan2016.sched.com/event/7ES4/kasan-in-bare-metal-hypervisor-alexander-popov-positive-technologies
[5]: /img/Alexander_Popov-KASan_in_a_Bare-Metal_Hypervisor.pdf

[6]: https://program.sha2017.org/events/295.html
[7]: /img/Alexander_Popov-Race_for_Root_SHA2017.pdf
[8]: https://media.ccc.de/v/SHA2017-295-race_for_root_the_analysis_of_the_linux_kernel_race_condition_exploit

[9]: https://ostconf.com/en/events/9745/materials/2344
[10]: /img/Alexander_Popov-stackleak-LinuxPiter2017.pdf
[11]: https://www.youtube.com/watch?v=oF8K9-8fXMQ

[12]: https://lssna18.sched.com/event/FLYJ/stackleak-a-long-way-to-the-linux-kernel-mainline-alexander-popov-positive-technologies
[13]: /img/Alexander_Popov-stackleak-LSS_NA_2018.pdf
[14]: https://www.youtube.com/watch?v=5wIniiWSgUc

[15]: https://osseu18.sched.com/event/FxY1/between-the-millstones-lessons-of-self-funded-participation-in-kernel-self-protection-project-alexander-popov-positive-technologies
[16]: /img/Alexander_Popov-KSPP_lessons.pdf

[17]: https://ostconf.com/ru/materials/2491
[18]: /img/Alexander_Popov-KSPP_lessons-Linux_Piter_2018.pdf
[19]: https://www.youtube.com/watch?v=LeKBVgTE6YY

[20]: https://www.isprasopen.ru/2019/
[21]: /img/Alexander_Popov-Linux_kernel_fuzzing_in_practice.pdf
[22]: http://0x1.tv/20191206AG

[23]: https://www.offensivecon.org/speakers/2020/alexander-popov.html
[24]: /img/Alexander_Popov-CVE-2019-18683.pdf
[25]: https://www.youtube.com/watch?v=J6xIohyARSU

[26]: https://lssna2020.sched.com/event/c898
[27]: https://youtu.be/v7_mwg5f2cE?list=PLbzoR-pLrL6rph1P4IRTbLweZXE9SnHU6&t=70

[28]: https://linuxplumbersconf.org/event/7/contributions/775/
[29]: /img/Alexander_Popov-Following_the_Linux_Kernel_Defence_Map.pdf
[30]: https://www.youtube.com/watch?v=4c01jjbQmBc&feature=youtu.be&t=8555
[31]: https://github.com/a13xp0p0v/linux-kernel-defence-map
[32]: https://github.com/a13xp0p0v/kconfig-hardened-check


[33]: https://web.archive.org/web/20210308095728/http://zer0con.org/#speaker-section
[34]: https://a13xp0p0v.github.io/img/CVE-2021-26708.pdf
[35]: https://nvd.nist.gov/vuln/detail/CVE-2021-26708
[36]: https://seclists.org/oss-sec/2021/q1/107
[37]: https://www.youtube.com/watch?v=EMcjHfceX44

[38]: https://www.phdays.com/ru/program/reports/4-bytes-of-power-exploiting-cve-2021-26708-in-the-linux-kernel/
[39]: https://a13xp0p0v.github.io/img/PHDays10_CVE-2021-26708.pdf
[40]: https://standoff365.com/phdays10/schedule/tech/4-bytes-of-power-exploiting-cve-2021-26708-in-the-linux-kernel

