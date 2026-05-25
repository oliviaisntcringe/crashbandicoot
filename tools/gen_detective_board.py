#!/usr/bin/env python3
"""
gen_detective_board.py — доска следопыта: AT&T / NSA / Hikvision
"""

import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, Circle, FancyArrowPatch
import matplotlib.patheffects as pe
import numpy as np

OUT = os.path.join(os.path.dirname(__file__), '..', 'docs', 'graphs')
os.makedirs(OUT, exist_ok=True)

# ── цвета ──────────────────────────────────────────────────────────────────
CORK       = '#2b1d0e'          # тёмная пробковая доска
CORK_LIGHT = '#3a2512'
PAPER      = '#f5f0e8'          # бумага / карточка
PAPER_OLD  = '#ede0c4'
RED_STR    = '#cc1111'          # красная нить
RED_DARK   = '#8b0000'
YELLOW_PIN = '#ffd700'
PIN_RED    = '#ff2222'
PIN_BLUE   = '#3399ff'
TEXT_DARK  = '#1a0a00'
TEXT_RED   = '#8b0000'
STAMP_RED  = '#cc2200'
GREEN_OK   = '#226622'
GREY_NOTE  = '#d4c9b0'

fig, ax = plt.subplots(figsize=(18, 11))
fig.patch.set_facecolor(CORK)
ax.set_facecolor(CORK)
ax.set_xlim(0, 18)
ax.set_ylim(0, 11)
ax.axis('off')

# ── фоновая текстура (точки как дырки от пинов) ────────────────────────────
rng = np.random.default_rng(42)
for _ in range(280):
    x = rng.uniform(0.2, 17.8)
    y = rng.uniform(0.2, 10.8)
    ax.plot(x, y, 'o', ms=0.6, color='#1a0d05', alpha=0.35, zorder=0)

# ── заголовок доски ────────────────────────────────────────────────────────
ax.text(9, 10.55,
        '⊕  INVESTIGATION BOARD  —  WHO OWNS YOUR CAMERA?  ⊕',
        ha='center', va='center', fontsize=16, fontweight='bold',
        color='#f5e6c8', fontfamily='monospace',
        path_effects=[pe.withStroke(linewidth=3, foreground=CORK)])

# ══════════════════════════════════════════════════════════════════════════════
# helper: карточка
# ══════════════════════════════════════════════════════════════════════════════
def card(ax, x, y, w, h, color=PAPER, title='', lines=None,
         title_color=TEXT_DARK, border=TEXT_DARK, alpha=0.96,
         title_size=10, line_size=8.5, stamp=None, stamp_color=STAMP_RED):
    rect = FancyBboxPatch((x, y), w, h,
                          boxstyle='round,pad=0.06',
                          facecolor=color, edgecolor=border,
                          linewidth=1.6, alpha=alpha, zorder=3)
    ax.add_patch(rect)
    ax.text(x + w/2, y + h - 0.14, title,
            ha='center', va='top', fontsize=title_size,
            fontweight='bold', color=title_color,
            fontfamily='monospace', zorder=4)
    if lines:
        for i, ln in enumerate(lines):
            ax.text(x + 0.1, y + h - 0.36 - i*0.20, ln,
                    ha='left', va='top', fontsize=line_size,
                    color=TEXT_DARK, fontfamily='monospace', zorder=4)
    if stamp:
        ax.text(x + w - 0.12, y + 0.16, stamp,
                ha='right', va='bottom', fontsize=8,
                color=stamp_color, fontweight='bold',
                fontfamily='monospace', alpha=0.75,
                rotation=-12, zorder=5)


def pin(ax, x, y, color=PIN_RED, size=7):
    circle = Circle((x, y), 0.09, color=color, zorder=10)
    ax.add_patch(circle)
    ax.plot(x, y, 'o', ms=size*0.7, color=color, zorder=10, alpha=0.9)
    ax.plot(x, y, 'o', ms=size*0.3, color='white', zorder=11, alpha=0.7)


def string(ax, x1, y1, x2, y2, color=RED_STR, lw=1.8, style='-', alpha=0.85):
    # лёгкий изгиб через контрольную точку
    cx = (x1 + x2) / 2 + rng.uniform(-0.3, 0.3)
    cy = (y1 + y2) / 2 + rng.uniform(-0.2, 0.2)
    from matplotlib.path import Path
    import matplotlib.patches as mpatches
    verts = [(x1, y1), (cx, cy), (x2, y2)]
    codes = [Path.MOVETO, Path.CURVE3, Path.LINETO]
    path = Path(verts, codes)
    patch = mpatches.PathPatch(path, facecolor='none',
                               edgecolor=color, lw=lw,
                               linestyle=style, alpha=alpha, zorder=2)
    ax.add_patch(patch)


# ══════════════════════════════════════════════════════════════════════════════
# КАРТОЧКИ
# ══════════════════════════════════════════════════════════════════════════════

# [A] HIKVISION  ─── верхний левый
AX, AY, AW, AH = 0.5, 7.0, 3.4, 2.8
card(ax, AX, AY, AW, AH,
     color='#f0e0d0', border='#8b3a00',
     title='▌ HIKVISION ▐',
     title_color='#8b0000',
     title_size=12,
     lines=[
         '• Основана: 2001, Ханчжоу',
         '• Мажоритарный акционер:',
         '  CETC (гос. ВПК КНР)',
         '• 40%+ мирового рынка CCTV',
         '• Entity List США (2019)',
         '• FCC запрет (2022)',
         '• CVE-2017-7921 — бэкдор',
         '  3 года в прошивках',
     ],
     stamp='САНКЦИИ', stamp_color='#8b0000')
pin(ax, AX + AW/2, AY + AH + 0.05, color=PIN_RED)

# [B] HARDCODED IP ─── центр верхний (главная улика)
BX, BY, BW, BH = 6.8, 7.2, 4.4, 2.6
card(ax, BX, BY, BW, BH,
     color='#fff8dc', border=RED_DARK,
     title='⚠  172.9.4.222  ⚠',
     title_color=RED_DARK,
     title_size=13,
     lines=[
         '  m_szHostName = "172.9.4.222"',
         '  → найдено в common.js прошивки',
         '',
         '  172.9.x.x ≠ RFC1918 private',
         '  → это ПУБЛИЧНЫЙ адрес',
         '',
         '  Host: 172.9.4.222 → HTTP 000',
         '  Host: <любой>     → HTTP 401',
         '  → сервер ЗНАЕТ этот адрес',
     ],
     stamp='УЛИКА #1', stamp_color=RED_DARK)
pin(ax, BX + BW/2, BY + BH + 0.05, color='#ff6600', size=9)

# [C] AT&T ─── верхний правый
CX, CY, CW, CH = 12.8, 7.0, 4.2, 2.8
card(ax, CX, CY, CW, CH,
     color='#e8f0f8', border='#003399',
     title='▌ AT&T ENTERPRISES ▐',
     title_color='#003399',
     title_size=11,
     lines=[
         'WHOIS: 172.0.0.0/12',
         'OrgName: AT&T Enterprises LLC',
         'Address: 208 S. Akard St.',
         '         Dallas, TX 75202',
         '',
         '→ IP-пространство того же',
         '  блока, что и 172.9.4.222',
     ],
     stamp='WHOIS ✓')
pin(ax, CX + CW/2, CY + CH + 0.05, color=PIN_BLUE)

# [D] NSA / ROOM 641A ─── правый центр
DX, DY, DW, DH = 13.2, 3.8, 4.5, 3.0
card(ax, DX, DY, DW, DH,
     color='#1a1a2e', border='#4444aa',
     title='█ NSA — ROOM 641A █',
     title_color='#aaaaff',
     lines=[
         '• 17 AT&T-хабов с NSA-оборудов.',
         '• 8 "крепостей": NYC, LA, DC...',
         '• Fairview (2003):',
         '  400 млрд метаданных в мес.',
         '  >1 млн email/день → Fort Meade',
         '• 1.1 млрд записей звонков/день',
         '  (с 2011, Сноуден 2013)',
         '• FISA Amendments Act 2008:',
         '  ретроактивный иммунитет AT&T',
     ],
     stamp='СЕКРЕТНО', stamp_color='#ff4444',
     title_size=11, line_size=8)
# overwrite text colors for dark card
ax.text(DX + DW/2, DY + DH - 0.14, '█ NSA — ROOM 641A █',
        ha='center', va='top', fontsize=11, fontweight='bold',
        color='#aaaaff', fontfamily='monospace', zorder=6)
for i, ln in enumerate([
    '• 17 AT&T-хабов с NSA-оборудов.',
    '• 8 "крепостей": NYC, LA, DC...',
    '• Fairview (2003):',
    '  400 млрд метаданных в мес.',
    '  >1 млн email/день → Fort Meade',
    '• 1.1 млрд записей звонков/день',
    '• FISA Amendments Act 2008:',
    '  ретроактивный иммунитет AT&T',
]):
    ax.text(DX + 0.12, DY + DH - 0.36 - i*0.27, ln,
            ha='left', va='top', fontsize=8,
            color='#ccccee', fontfamily='monospace', zorder=6)
pin(ax, DX + DW/2, DY + DH + 0.05, color=PIN_BLUE)

# [E] МИЛЛИОНЫ УСТРОЙСТВ ─── нижний левый
EX, EY, EW, EH = 0.5, 2.8, 3.8, 2.8
card(ax, EX, EY, EW, EH,
     color='#f8f0e0', border='#666633',
     title='▌ МАСШТАБ ▐',
     title_color='#555500',
     title_size=11,
     lines=[
         '~2.2 млн Hikvision',
         'устройств в Shodan',
         '',
         'Банки, офисы, дома,',
         'больницы, тюрьмы...',
         '',
         '"Embedded Net DVR"',
         'port:554 — всегда онлайн',
     ],
     stamp='УГРОЗА')
pin(ax, EX + EW/2, EY + EH + 0.05, color=YELLOW_PIN, size=8)

# [F] CVE-2017-7921 ─── нижний центр-лево
FX, FY, FW, FH = 5.5, 2.6, 3.8, 3.0
card(ax, FX, FY, FW, FH,
     color='#f5e0e0', border=RED_DARK,
     title='CVE-2017-7921',
     title_color=RED_DARK,
     lines=[
         'Задокументированный',
         'бэкдор Hikvision',
         '────────────────────',
         'Присутствовал:',
         '2014 → 2017 (3 года)',
         '',
         'Обход аутентификации',
         'через URL-параметр',
         '',
         'Hikvision: "случайный',
         ' отладочный код" 🤔',
     ],
     line_size=8,
     stamp='0-DAY WAS HERE')
pin(ax, FX + FW/2, FY + FH + 0.05, color=PIN_RED)

# [G] ВЫВОД ─── нижний правый
GX, GY, GW, GH = 10.0, 1.2, 7.5, 2.2
card(ax, GX, GY, GW, GH,
     color='#1a0000', border=RED_STR,
     title=None,
     lines=[], alpha=0.95)
ax.text(GX + GW/2, GY + GH - 0.2,
        '⚡  ВЫВОД  ⚡',
        ha='center', va='top', fontsize=13, fontweight='bold',
        color=RED_STR, fontfamily='monospace', zorder=6)
ax.text(GX + GW/2, GY + GH - 0.55,
        'Китайская госкомпания вшила в прошивку публичный IP из блока\n'
        'главного партнёра АНБ США. Случайно или намеренно —\n'
        'архитектура создаёт технически работоспособный канал слежки.',
        ha='center', va='top', fontsize=9.5,
        color='#ffcccc', fontfamily='monospace',
        linespacing=1.5, zorder=6)
pin(ax, GX + GW/2, GY + GH + 0.05, color=PIN_RED, size=8)

# [H] липкая заметка — наш DVR
HX, HY, HW, HH = 4.8, 5.2, 2.6, 1.8
card(ax, HX, HY, HW, HH,
     color='#fffaaa', border='#ccbb00',
     title='НАШ DVR',
     title_color='#554400',
     lines=[
         'HiSilicon Hi3531',
         'fw: 3050060...011',
         'UA overflow → 9.8',
         '+ 5 других 0-days',
     ],
     line_size=8, title_size=10)
pin(ax, HX + HW/2, HY + HH + 0.04, color=YELLOW_PIN, size=7)

# ══════════════════════════════════════════════════════════════════════════════
# НИТИ
# ══════════════════════════════════════════════════════════════════════════════

# Hikvision → IP
string(ax, AX+AW, AY+AH*0.7,  BX, BY+BH*0.7,       color=RED_STR, lw=2.2)
pin(ax, AX+AW+0.02, AY+AH*0.7, color=PIN_RED, size=5)
pin(ax, BX-0.02,   BY+BH*0.7,  color=PIN_RED, size=5)

# IP → AT&T
string(ax, BX+BW, BY+BH*0.75,  CX, CY+CH*0.75,      color=RED_STR, lw=2.2)
pin(ax, BX+BW+0.02, BY+BH*0.75, color=PIN_RED, size=5)
pin(ax, CX-0.02,   CY+CH*0.75,  color=PIN_RED, size=5)

# AT&T → NSA
string(ax, CX+CW*0.7, CY,  DX+DW*0.7, DY+DH,        color='#4444ff', lw=2.0)
pin(ax, CX+CW*0.7, CY-0.02, color=PIN_BLUE, size=5)
pin(ax, DX+DW*0.7, DY+DH+0.02, color=PIN_BLUE, size=5)

# Hikvision → CVE
string(ax, AX+AW*0.3, AY, FX+FW*0.3, FY+FH,          color=RED_STR, lw=1.6, alpha=0.7)
pin(ax, AX+AW*0.3, AY-0.02, color=PIN_RED, size=4)
pin(ax, FX+FW*0.3, FY+FH+0.02, color=PIN_RED, size=4)

# Hikvision → масштаб
string(ax, AX+AW*0.1, AY, EX+EW*0.5, EY+EH,          color='#886600', lw=1.5, alpha=0.7)
pin(ax, AX+AW*0.1, AY-0.02, color=YELLOW_PIN, size=4)
pin(ax, EX+EW*0.5, EY+EH+0.02, color=YELLOW_PIN, size=4)

# наш DVR → IP
string(ax, HX+HW*0.5, HY+HH, BX+BW*0.4, BY,           color='#cccc00', lw=1.5, alpha=0.8)
pin(ax, HX+HW*0.5, HY+HH+0.02, color=YELLOW_PIN, size=4)
pin(ax, BX+BW*0.4, BY-0.02,    color=YELLOW_PIN, size=4)

# CVE → вывод
string(ax, FX+FW, FY+FH*0.3, GX, GY+GH*0.5,            color=RED_STR, lw=1.6, alpha=0.7)
pin(ax, FX+FW+0.02, FY+FH*0.3, color=PIN_RED, size=4)
pin(ax, GX-0.02, GY+GH*0.5,    color=PIN_RED, size=4)

# NSA → вывод
string(ax, DX+DW*0.3, DY, GX+GW*0.85, GY+GH,           color='#4444ff', lw=1.6, alpha=0.65)
pin(ax, DX+DW*0.3, DY-0.02,  color=PIN_BLUE, size=4)
pin(ax, GX+GW*0.85, GY+GH+0.02, color=PIN_BLUE, size=4)

# масштаб → вывод
string(ax, EX+EW, EY+EH*0.2, GX, GY+GH*0.2,             color='#886600', lw=1.4, alpha=0.6)

# IP → вывод (главная нить)
string(ax, BX+BW*0.7, BY, GX+GW*0.4, GY+GH,             color=RED_STR, lw=2.5, alpha=0.9)
pin(ax, BX+BW*0.7, BY-0.02, color=PIN_RED, size=6)
pin(ax, GX+GW*0.4, GY+GH+0.02, color=PIN_RED, size=6)

# ── легенда нитей ──────────────────────────────────────────────────────────
legend_x, legend_y = 0.3, 1.15
ax.plot([legend_x, legend_x+0.5], [legend_y, legend_y],
        color=RED_STR, lw=2, zorder=8)
ax.text(legend_x+0.6, legend_y, '— связь Hikvision/IP',
        va='center', fontsize=7.5, color='#ffaaaa', fontfamily='monospace')
ax.plot([legend_x, legend_x+0.5], [legend_y-0.28, legend_y-0.28],
        color='#4444ff', lw=2, zorder=8)
ax.text(legend_x+0.6, legend_y-0.28, '— связь AT&T/NSA',
        va='center', fontsize=7.5, color='#aaaaff', fontfamily='monospace')

# ── подпись ────────────────────────────────────────────────────────────────
ax.text(9, 0.35,
        'Все факты основаны на публичных данных: WHOIS, документы Сноудена (ProPublica/NYT 2015), CVE NVD, FCC order 2022, WHOIS ARIN',
        ha='center', va='center', fontsize=7.5,
        color='#8a7a6a', fontfamily='monospace', style='italic')

plt.tight_layout(pad=0.3)
path = os.path.join(OUT, '05_detective_board.png')
plt.savefig(path, dpi=160, bbox_inches='tight', facecolor=CORK)
plt.close()
print(f'✓ {path}')
