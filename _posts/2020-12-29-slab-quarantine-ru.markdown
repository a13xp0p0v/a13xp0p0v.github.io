---
layout: post
title:  "[ru] Карантин для динамической памяти ядра Linux"
date:   2020-12-29 13:37:00 +0300
---

2020 год. Повсюду карантин. И эта статья тоже про карантин, но он другого рода.

Я расскажу об экспериментах с __карантином для динамической памяти ядра Linux__. Это механизм безопасности, противодействующий использованию памяти после освобождения (use-after-free или UAF) в ядре Linux. Я также подведу итоги обсуждения моей патч-серии в списке рассылки ядра (Linux Kernel Mailing List, LKML).

# Использование памяти после освобождения в ядре Linux

UAF в ядре Linux — очень популярный для эксплуатации тип уязвимостей. Есть множество публичных прототипов ядерных эксплойтов для UAF:
 - [CVE-2016-8655][1],
 - [CVE-2017-6074][2],
 - [CVE-2017-2636][3],
 - [CVE-2017-15649][4],
 - [CVE-2019-18683][5].

Для эксплуатации UAF обычно применяется техника __heap spraying__. Цель данной техники — разместить данные, контролируемые атакующим, в определенном участке динамической памяти, которая также называется «кучей». Техника heap spraying для эксплуатации UAF в ядре Linux основана на том, что при вызове `kmalloc()` slab-аллокатор возвращает адрес участка памяти, который был недавно освобожден:

<center><a href="/img/no_quarantine.png"><img src="/img/no_quarantine.png" width="60%"/></a></center>
<br>

То есть создание другого ядерного объекта такого же размера с контролируемым содержимым позволяет переписать освобожденный уязвимый объект:

<center><a href="/img/uaf.png"><img src="/img/uaf.png" width="70%"/></a></center>
<br>

Примечание: heap spraying для эксплуатации переполнения буфера в куче — отдельная техника, которая работает иначе.

# Идея

В июле 2020 года у меня возникла идея, как можно противостоять технике heap spraying для эксплуатации UAF в ядре Linux. В августе я нашел время поэкспериментировать. Я выделил карантин для slab-аллокатора из функциональности [KASAN][6] и назвал его `SLAB_QUARANTINE`.

При активации этого механизма освобожденные аллокации размещаются в карантинной очереди, где ожидают реального освобождения. Поэтому они не могут быть мгновенно реаллоцированы и переписаны эксплойтами UAF. То есть при активации `SLAB_QUARANTINE` аллокатор ядра ведет себя следующим образом:

<center><a href="/img/with_quarantine.png"><img src="/img/with_quarantine.png" width="60%"/></a></center>
<br>

13 августа [я отправил][7] первый ранний прототип карантина в LKML и начал более глубокое исследование параметров безопасности этого механизма.

# Свойства безопасности SLAB_QUARANTINE

Для исследования свойств безопасности карантина для динамической памяти ядра я разработал два теста `lkdtm` ([опубликованы в серии патчей][8]).

Первый тест называется `lkdtm_HEAP_SPRAY`. Он выделяет и освобождает один объект из отдельного `kmem_cache`, а затем выделяет 400 000 аналогичных объектов. Другими словами, этот тест имитирует оригинальную технику heap spraying для эксплуатации UAF:

```c
#define SPRAY_LENGTH 400000
    ...
    addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
    ...
    kmem_cache_free(spray_cache, addr);
    pr_info("Allocated and freed spray_cache object %p of size %d\n",
                    addr, SPRAY_ITEM_SIZE);
    ...
    pr_info("Original heap spraying: allocate %d objects of size %d...\n",
                    SPRAY_LENGTH, SPRAY_ITEM_SIZE);
    for (i = 0; i < SPRAY_LENGTH; i++) {
        spray_addrs[i] = kmem_cache_alloc(spray_cache, GFP_KERNEL);
        ...
        if (spray_addrs[i] == addr) {
            pr_info("FAIL: attempt %lu: freed object is reallocated\n", i);
            break;
        }
    }
    
    if (i == SPRAY_LENGTH)
        pr_info("OK: original heap spraying hasn't succeeded\n");
```

Если отключить `CONFIG_SLAB_QUARANTINE`, освобожденный объект немедленно реаллоцируется и переписывается:

```
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
   lkdtm: Performing direct entry HEAP_SPRAY
   lkdtm: Allocated and freed spray_cache object 000000002b5b3ad4 of size 333
   lkdtm: Original heap spraying: allocate 400000 objects of size 333...
   lkdtm: FAIL: attempt 0: freed object is reallocated
```

Если включить `CONFIG_SLAB_QUARANTINE`, 400 000 новых аллокаций не переписывают освобожденный объект:

```
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
   lkdtm: Performing direct entry HEAP_SPRAY
   lkdtm: Allocated and freed spray_cache object 000000009909e777 of size 333
   lkdtm: Original heap spraying: allocate 400000 objects of size 333...
   lkdtm: OK: original heap spraying hasn't succeeded
```

Это происходит из-за того, что для прохождения объекта через карантин требуется __и выделение, и освобождения памяти__. Объекты выпускаются из карантина, когда выделяется новая память, но только если карантин превысил свой предельный размер. А размер карантина увеличивается при освобождении памяти.

Поэтому я разработал второй тест под названием `lkdtm_PUSH_THROUGH_QUARANTINE`. Он выделяет и освобождает один объект из отдельного `kmem_cache` и затем выполняет `kmem_cache_alloc()+kmem_cache_free()` для этого кэша 400 000 раз.

```c
    addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
    ...
    kmem_cache_free(spray_cache, addr);
    pr_info("Allocated and freed spray_cache object %p of size %d\n",
                    addr, SPRAY_ITEM_SIZE);

    pr_info("Push through quarantine: allocate and free %d objects of size %d...\n",
                    SPRAY_LENGTH, SPRAY_ITEM_SIZE);
    for (i = 0; i < SPRAY_LENGTH; i++) {
        push_addr = kmem_cache_alloc(spray_cache, GFP_KERNEL);
        ...
        kmem_cache_free(spray_cache, push_addr);

        if (push_addr == addr) {
            pr_info("Target object is reallocated at attempt %lu\n", i);
            break;
        }
    }

    if (i == SPRAY_LENGTH) {
        pr_info("Target object is NOT reallocated in %d attempts\n",
                    SPRAY_LENGTH);
    }
```

При этом тесте объект проходит через карантин и реаллоцируется после своего возвращения в список свободных объектов аллокатора:

```
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000008fdb15c3 of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 182994
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000004e223cbe of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 186830
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000007663a058 of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 182010
```

Как можно заметить, количество аллокаций, необходимых для переписывания уязвимого объекта, почти не изменяется. Это плохо для защиты и хорошо для атакующего, поскольку дает возможность для стабильного обхода карантина за счет более длительного спрея. Поэтому я разработал [__рандомизацию карантина__][9]. В сущности это небольшая хитроумная доработка во внутреннем механизме работы с карантинной очередью.

В карантине объекты хранятся в «пачках». Рандомизация работает так: сначала все пачки наполняются ядерными объектами. А потом, когда карантин превысил предельный размер и должен выпустить лишние объекты, выбирается произвольная пачка, из которой освобождается примерно половина всех ядерных объектов, которые тоже выбираются произвольно. Теперь карантин отпускает освобожденный объект в непредсказуемый момент:

```
   lkdtm: Target object is reallocated at attempt 107884
   lkdtm: Target object is reallocated at attempt 265641
   lkdtm: Target object is reallocated at attempt 100030
   lkdtm: Target object is NOT reallocated in 400000 attempts
   lkdtm: Target object is reallocated at attempt 204731
   lkdtm: Target object is reallocated at attempt 359333
   lkdtm: Target object is reallocated at attempt 289349
   lkdtm: Target object is reallocated at attempt 119893
   lkdtm: Target object is reallocated at attempt 225202
   lkdtm: Target object is reallocated at attempt 87343
```

Однако такая рандомизация сама по себе не предотвратит эксплуатацию: объекты в карантине содержат данные атакующего (полезную нагрузку эксплойта). Это значит, что целевой объект ядра, реаллоцированный и переписанный спреем, будет содержать данные атакующего до следующей реаллокации (очень плохо).

Поэтому важно __очищать объекты ядерной кучи до помещения их в карантин__. Более того, заполнение их нулями в некоторых случаях позволяет обнаружить использование памяти после освобождения: происходит разыменование нулевого указателя. Такой функционал уже существует в ядре и называется `init_on_free`. [Я интегрировал его][10] с `CONFIG_SLAB_QUARANTINE`.

В ходе этой работы я обнаружил ошибку в ядре: в `CONFIG_SLAB` функция `init_on_free` осуществляется слишком поздно, и ядерные объекты отправляются на карантин без очистки. Я подготовил исправление в [отдельном патче][11] (принят в mainline).

Для более глубокого понимания того, как работает `CONFIG_SLAB_QUARANTINE` с рандомизацией, я подготовил [дополнительный патч][12], с подробным отладочным выводом (патч не для принятия в mainline). Пример такого отладочного вывода:

```
   quarantine: PUT 508992 to tail batch 123, whole sz 65118872, batch sz 508854
   quarantine: whole sz exceed max by 494552, REDUCE head batch 0 by 415392, leave 396304
   quarantine: data level in batches:
     0 - 77%
     1 - 108%
     2 - 83%
     3 - 21%
   ...
     125 - 75%
     126 - 12%
     127 - 108%
   quarantine: whole sz exceed max by 79160, REDUCE head batch 12 by 14160, leave 17608
   quarantine: whole sz exceed max by 65000, REDUCE head batch 75 by 218328, leave 195232
   quarantine: PUT 508992 to tail batch 124, whole sz 64979984, batch sz 508854
   ...
```

Операция `PUT` осуществляется в ходе освобождения ядерной памяти. Операция `REDUCE` осуществляется в ходе выделения ядерной памяти, когда превышен размер карантина. Объекты ядра, выпущенные из карантина, возвращаются в список свободных объектов аллокатора. Также в этом выводе можно видеть, что при осуществлении операции `REDUCE` карантин отпускает часть объектов из произвольно выбранной пачки.

# А что с производительностью?

Я провел [несколько тестов][14] производительности моего прототипа на реальном оборудовании и на виртуальных машинах:
  1. Тестирование пропускной способности сети с помощью `iperf`: <br>
     сервер: `iperf -s -f K` <br>
     клиент: `iperf -c 127.0.0.1 -t 60 -f K`

  2. Нагрузочный тест ядерного планировщика задач: <br>
     `hackbench -s 4000 -l 500 -g 15 -f 25 -P`

  3. Сборка ядра в конфигурации по умолчанию: <br>
     `time make -j2`

Я тестировал ванильное ядро Linux в трех режимах:
 - `init_on_free=off`
 - `init_on_free=on` (механизм из официального ядра)
 - `CONFIG_SLAB_QUARANTINE=y` (включает в себя `init_on_free`)

Тестирование пропускной способности сети с помощью `iperf` показало, что:
 - `init_on_free=on` дает пропускную способность на __28%__ ниже, чем `init_on_free=off`.
 - `CONFIG_SLAB_QUARANTINE` дает пропускную способность на __2%__ ниже, чем `init_on_free=on`.

Нагрузочный тест ядерного планировщика задач:
 - `hackbench` работает на __5,3%__ медленнее с `init_on_free=on` по сравнению с `init_on_free=off`.
 - `hackbench` работает на __91,7%__ медленнее с `CONFIG_SLAB_QUARANTINE` по сравнению с `init_on_free=on`. При этом тестирование на виртуальной машине QEMU/KVM показало снижение производительности на __44%__, что существенно отличается от результатов тестирования на реальном оборудовании (Intel Core i7-6500U CPU).

Сборка ядра в конфигурации по умолчанию:
 - При `init_on_free=on` сборка ядра осуществлялась на __1,7%__ медленнее, чем с `init_on_free=off`.
 - При `CONFIG_SLAB_QUARANTINE`сборка ядра осуществлялась на __1,1%__ медленнее, чем с `init_on_free=on`.

Как вы можете видеть, результаты тестов сильно варьируются и зависят от типа рабочей нагрузки.

Примечание: для этой версии прототипа карантина НЕ проводилась оптимизация производительности. Моей главной задачей было исследование свойств безопасности механизма. Я решил, что оптимизацией производительности лучше заняться позже, если станет ясно, что идея удачная.

# Контратака

В LKML получилось интересное обсуждение `CONFIG_SLAB_QUARANTINE`. Спасибо разработчикам ядра, которые уделили время и дали детальную обратную связь на мою серию патчей. Это Кейс Кук (Kees Cook), Андрей Коновалов, Александр Потапенко, Мэттью Уилкокс (Matthew Wilcox), Дэниел Майкей (Daniel Micay), Кристофер Ламетер (Christopher Lameter), Павел Мачек (Pavel Machek) и Эрик Бидерман (Eric W. Biederman).

Особенно я благодарен Яну Хорну (Jann Horn). Он придумал контратаку, с помощью которой все-таки удается обойти `CONFIG_SLAB_QUARANTINE` и проэксплуатировать UAF в ядре Linux.

Примечательно, что наша дискуссия с Яном состоялась одновременно со стримом Кейса в Twitch, в ходе которого он тестировал мои патчи (рекомендую посмотреть [запись][15]).

Цитата из переписки с идеей контратаки:

```
On 06.10.2020 21:37, Jann Horn wrote:
> On Tue, Oct 6, 2020 at 7:56 PM Alexander Popov wrote:
>> So I think the control over the time of the use-after-free access doesn't help
>> attackers, if they don't have an "infinite spray" -- unlimited ability to store
>> controlled data in the kernelspace objects of the needed size without freeing them.
   [...]
>> Would you agree?
>
> But you have a single quarantine (per CPU) for all objects, right? So
> for a UAF on slab A, the attacker can just spam allocations and
> deallocations on slab B to almost deterministically flush everything
> in slab A back to the SLUB freelists?

Aaaahh! Nice shot Jann, I see.

Another slab cache can be used to flush the randomized quarantine, so eventually
the vulnerable object returns into the allocator freelist in its cache, and
original heap spraying can be used again.

For now I think the idea of a global quarantine for all slab objects is dead.
```

То есть атакующий может воспользоваться другим slab-кэшем в ядерном аллокаторе, выделить и освободить в нем большое количество объектов, что приведет к вытеснению целевого объекта из карантина обратно в список свободных объектов. После этого атакующий может воспользоваться стандартной техникой heap spraying для эксплуатации UAF.

Я сразу поделился этой перепиской в чате стрима Кейса в Twitch. Он доработал мой тест `PUSH_THROUGH_QUARANTINE` по идее Яна и выполнил атаку. Бабах!

Очень советую прочитать [эту переписку в LKML][16] целиком. Там обсуждаются новые идеи противодействия эксплуатации UAF в ядре.

# Заключение

Я исследовал свойства безопасности карантина для динамической памяти ядра Linux, провел эксперименты, показывающие его влияние на эксплуатацию уязвимостей use-after-free. Получился быстрый и интересный проект. Надежное средство защиты, примененное в mainline, создать не удалось, но мы получили полезные результаты и идеи, которые пригодятся в дальнейших работах по защите ядра Linux.

А пока что позвольте закончить небольшим стихотворением, которое пришло мне в голову перед сном:

```
  Quarantine patch version three
  Won't appear. No need.
  Let's exploit use-after-free
  Like we always did ;)
  
	-- a13xp0p0v
```

[1]: https://seclists.org/oss-sec/2016/q4/607
[2]: https://www.openwall.com/lists/oss-security/2017/02/26/2
[3]: https://a13xp0p0v.github.io/2017/03/24/CVE-2017-2636.html
[4]: https://ssd-disclosure.com/ssd-advisory-linux-kernel-af_packet-use-after-free/
[5]: https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html
[6]: https://www.kernel.org/doc/html/latest/dev-tools/kasan.html
[7]: https://www.openwall.com/lists/kernel-hardening/2020/08/13/7
[8]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/7
[9]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/6
[10]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/5
[11]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/4
[12]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/8
[13]: https://www.openwall.com/lists/kernel-hardening/2020/09/29/6
[14]: https://www.openwall.com/lists/kernel-hardening/2020/10/01/7
[15]: https://www.youtube.com/watch?v=1sBMwnKNSw0
[16]: https://lore.kernel.org/kernel-hardening/20200929183513.380760-1-alex.popov@linux.com/T/#u
