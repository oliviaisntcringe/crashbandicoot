# Shodan дорки — Hikvision DVR / HiSilicon Hi3531

Все дорки заточены под устройства с открытым RTSP-портом 554.  
Тестировать только на своих устройствах или с письменным разрешением владельца.

---

## Основные дорки

```
"Embedded Net DVR" port:554
```
```
server:"DVRDVS-Webs" port:554
```
```
"Embedded Net DVR" "jQuery 1.7.1" port:554
```
```
"DVRDVS" port:554
```

---

## Комбинированные (HTTP + RTSP)

```
"Embedded Net DVR" port:80,554
```
```
server:"DVRDVS-Webs" port:80,554
```

---

## С фильтром по стране

```
"Embedded Net DVR" port:554 country:RU
"Embedded Net DVR" port:554 country:CN
"Embedded Net DVR" port:554 country:UA
"Embedded Net DVR" port:554 country:BR
```

---

## По SoC / прошивке

```
"Hi3531" port:554
"HiSilicon" "DVR" port:554
```

---

## Расширенные — другие бренды на том же стеке

HiSilicon Hi3531/Hi3521/Hi3520D используется не только в Hikvision.  
Те же уязвимости потенциально применимы к:

```
"Embedded Net DVR" port:554
"XMEye" port:554
"NetSurveillance" port:554
"IPCAM" port:554 server:"uc-httpd"
```

---

## Фингерпринт нашего конкретного устройства

```
"Embedded Net DVR" "jQuery 1.7.1" "DVRDVS" port:554
```

| Поле | Значение |
|------|----------|
| Web-баннер | `Embedded Net DVR` |
| HTTP сервер | `DVRDVS-Webs` |
| JS-библиотека | jQuery 1.7.1 |
| Realm | `DVRDVS` |
| SoC | HiSilicon Hi3531 |
| Прошивка | `3050060061181310011` |
| RTSP порт | 554 |
| HTTP порт | 80 |

---

## Масштаб

| Запрос | Примерное кол-во |
|--------|-----------------|
| `hikvision` | ~2.2 млн |
| `server:hikvision-webs` | ~1.9 млн |
| `"Embedded Net DVR"` | подмножество DVR-класса |
| `"Embedded Net DVR" port:554` | уточнённая выборка с открытым RTSP |


---

*Co-authored with [Claude](https://claude.ai) (Anthropic)*
