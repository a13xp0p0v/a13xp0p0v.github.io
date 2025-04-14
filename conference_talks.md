---
layout: page
title: "Conference Talks"
permalink: /conference_talks/
---

# [Раскручиваем маховик: как развивать открытую разработку в коммерческой компании][58]

__Conference:__ TechLeadConf

__Date:__ 27.11.2024

[__Slides__][59] &nbsp; &nbsp; [__Video__][60]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/9qwm8aLmuOE" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Открытая разработка — удивительный инструмент, с помощью которого компания-производитель ПО способна решать такие задачи, для которых неприменимы обычные методы проприетарной разработки. Например, с помощью Open Source компания может занять важную технологическую нишу, создать сообщество разработчиков и экспертов вокруг своего продукта, популяризировать свой язык описания экспертизы.

Но работа с открытым кодом требует особых подходов и практик внутри компании. Поэтому для координации, наладки процессов и продвижения своих открытых проектов в зарубежных компаниях создают Open Source Program Office, OSPO.

В своем выступлении докладчик поделится опытом создания OSPO или комитета по открытому коду в российской компании-разработчике ПО. Александр взялся за эту задачу в Positive Technologies полтора года назад и за это время ощутил ее сложность во всей полноте. Он расскажет о непростом процессе культурного сдвига в сторону Open Source у разработчиков и их руководителей, о мозговых штурмах и выборе лучших практик открытой разработки. Докладчик также поделится полезными хитростями, которые помогают постепенно раскрутить маховик открытой разработки и достичь поставленных целей.

<br/>

# [A Bug Hunter’s Reflections on Fuzzing][53]

__Conference:__ HITB x PHDays

__Date:__ 25.05.2024

[__Slides__][54] &nbsp; &nbsp; [__Video__][55]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/wTbFmdx7wG8" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Fuzzing is an incredibly effective and popular technique for testing software. But not all the bugs that it finds are interesting for bug hunters. Fuzzing for vulnerability discovery is special, and in this talk, Alexander Popov will share his reflections on that topic inspired by his experience in Linux kernel fuzzing.

Attendees can expect a detailed analysis of the fuzzing process, the cases from Alexander’s vulnerability research practice, and insights on how to make fuzzing effective for bug hunting.

<br/>

# Как обезопасить от санкций ваш открытый проект на GitHub

__Conference:__ Positive Hack Days 12

__Date:__ 20.05.2023

[__Slides__][56] &nbsp; &nbsp; [__Video__][57]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/qT8rE07tGJw" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

На платформе GitHub зарегистрировано более 100 миллионов разработчиков. Это дает выход на огромную аудиторию, и поэтому многие open-source проекты разрабатываются там. С 2018 года компания Microsoft владеет платформой GitHub и в последнее время проводит на ней политику санкций и блокировок. В данном докладе Александр Попов расскажет о комплексе технических мер, которые позволяют снизить возможный ущерб от санкций для вашего открытого GitHub-проекта.

<br/>

# [Безопасность ядра Linux: в теории и на практике][50]

__Conference:__ HighLoad++ 2022

__Date:__ 25.11.2022

[__Slides__][51] &nbsp; &nbsp; [__Video__][52]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/Q0iZ6XTuJuM" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Безопасность ядра Linux — очень сложная предметная область. Она включает большое количество взаимосвязанных понятий: классы уязвимостей, техники их эксплуатации для проведения атак, механизмы выявления ошибок, технологии защиты ядра.

Александр Попов разработал карту средств защиты ядра Linux, которая отражает взаимосвязи между этими понятиями. В докладе он даст обзор текущего состояния безопасности Linux, используя данную карту, и расскажет о своем инструменте kconfig-hardened-check, который помогает управлять ядерными опциями безопасности.

<br/>

# [A Kernel Hacker Meets Fuchsia OS][47]

__Conference:__ Nullcon Goa 2022

__Date:__ 9.09.2022

[__Slides__][48] &nbsp; &nbsp; [__Video__][49]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/TZz-cbPp2uc" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Fuchsia is a general-purpose open-source operating system created by Google. It is based on the Zircon microkernel written in C++ and is currently under active development. The developers say that Fuchsia is designed with a focus on security, updatability, and performance.

As a Linux kernel hacker, Alexander decided to take a look at Fuchsia OS and assess it from the attacker's point of view. In this talk, he will share his findings.

<br/>

# [Fuchsia OS глазами атакующего][44]

__Conference:__ Positive Hack Days 11

__Date:__ 19.05.2022

[__Slides__][45] &nbsp; &nbsp; [__Video__][46]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/cW928eD8xJU" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

Fuchsia — это операционная система общего назначения с открытым исходным кодом. Она разрабатывается компанией Google. Эта операционная система построена на базе микроядра Zircon, код которого написан на C++. При проектировании Fuchsia главный приоритет был отдан безопасности, обновляемости и быстродействию.

Александр Попов как исследователь безопасности ядра Linux заинтересовался операционной системой Fuchsia и решил посмотреть на нее с точки зрения атакующего. В своем докладе он поделится результатами этой работы.

Вначале будет представлен обзор архитектуры безопасности операционной системы Fuchsia. Затем Александр расскажет о своих экспериментах по эксплуатации уязвимостей для микроядра Zircon и продемонстрирует, как путем повреждения ядерной памяти он внедрил руткит для Fuchsia.

Александр выполнил ответственное разглашение информации о проблемах безопасности, обнаруженных в ходе этого исследования.

<br/>

# [Improving the Exploit for CVE-2021-26708 in the Linux Kernel to Bypass LKRG][41]

__Conference:__  ZeroNights 2021

__Date:__ 25.08.2021

[__Slides__][42] &nbsp; &nbsp; [__Video__][43]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/jFgn0-9IzK0" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div><br />

__Description__

[CVE-2021-26708][35] is assigned to five race condition bugs in the virtual socket implementation of the Linux kernel. These vulnerabilities were discovered and fixed by Alexander Popov. Earlier, he demonstrated how to exploit them for local privilege escalation on Fedora 33 Server for x86_64. And in this talk, Alexander will describe how he improved this exploit to bypass the Linux Kernel Runtime Guard (LKRG).

<br/>

# Сила четырех байтов: эксплуатация уязвимости CVE-2021-26708 в ядре Linux

__Conference:__ Positive Hack Days 10

__Date:__ 20.05.2021

[__Slides__][39] &nbsp; &nbsp; [__Video__][40]

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/h8eL3ysrbcU" frameborder="0" allowfullscreen
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

[1]: https://web.archive.org/web/20180709090120/http://2016.phdays.ru/program/49625/
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
[34]: /img/CVE-2021-26708.pdf
[35]: https://nvd.nist.gov/vuln/detail/CVE-2021-26708
[36]: https://seclists.org/oss-sec/2021/q1/107
[37]: https://www.youtube.com/watch?v=EMcjHfceX44

[38]: https://standoff365.com/phdays10/schedule/tech/4-bytes-of-power-exploiting-cve-2021-26708-in-the-linux-kernel
[39]: /img/PHDays10_CVE-2021-26708.pdf
[40]: https://www.youtube.com/watch?v=h8eL3ysrbcU

[41]: https://web.archive.org/web/20210827082557/https://zeronights.ru/en/reports-en/improving-the-exploit-for-cve-2021-26708-in-the-linux-kernel-to-bypass-lkrg/
[42]: /img/CVE-2021-26708_LKRG_bypass.pdf
[43]: https://youtu.be/jFgn0-9IzK0

[44]: https://web.archive.org/web/20231206082353/https://event.phdays.com/ru#a-kernel-hacker-meets-fuchsia-os
[45]: /img/Alexander_Popov-Fuchsia_pwn-ru.pdf
[46]: https://www.youtube.com/watch?v=cW928eD8xJU

[47]: https://web.archive.org/web/20221211203018/https://nullcon.net/goa-2022/kernel-hacker-meets-fuchsia-os
[48]: /img/Alexander_Popov-Fuchsia_pwn.pdf
[49]: https://www.youtube.com/watch?v=TZz-cbPp2uc

[50]: https://highload.ru/moscow/2022/abstracts/9466
[51]: /img/Alexander_Popov-Linux_kernel_security_overview.pdf
[52]: https://www.youtube.com/watch?v=Q0iZ6XTuJuM

[53]: https://conference.hitb.org/hitbxphdays/#talk007
[54]: /img/Alexander_Popov-Reflections_on_Fuzzing.pdf
[55]: https://www.youtube.com/watch?v=wTbFmdx7wG8

[56]: img/Alexander_Popov-GitHub_Mirroring.pdf
[57]: https://www.youtube.com/watch?v=qT8rE07tGJw

[58]: https://techleadconf.ru/moscow/2024/abstracts/13662
[59]: img/techlead24.pdf
[60]: https://www.youtube.com/watch?v=9qwm8aLmuOE
