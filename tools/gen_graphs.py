#!/usr/bin/env python3
"""
gen_graphs.py — генератор графиков для Crashbandicoot research
Выводит 4 PNG в docs/graphs/
"""

import os, sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

OUT = os.path.join(os.path.dirname(__file__), '..', 'docs', 'graphs')
os.makedirs(OUT, exist_ok=True)

BG       = '#0d0d0d'
PANEL    = '#141414'
RED      = '#ff3333'
ORANGE   = '#ff8c00'
GREEN    = '#00ff88'
CYAN     = '#00e5ff'
PURPLE   = '#bf5fff'
YELLOW   = '#ffd700'
GREY     = '#444444'
LGREY    = '#888888'

plt.rcParams.update({
    'figure.facecolor': BG,
    'axes.facecolor':   PANEL,
    'axes.edgecolor':   GREY,
    'axes.labelcolor':  LGREY,
    'xtick.color':      LGREY,
    'ytick.color':      LGREY,
    'text.color':       '#e0e0e0',
    'grid.color':       GREY,
    'grid.linestyle':   '--',
    'grid.alpha':       0.4,
    'font.family':      'monospace',
})

# ─────────────────────────────────────────────────────────────────────────────
# 1. CVSS bar chart
# ─────────────────────────────────────────────────────────────────────────────
def graph_cvss():
    labels = ['[UA]\nUser-Agent', '[SC]\nScale', '[AC]\nAccept',
              '[TR]\nTransport', '[HH]\nHTTP Host', '[HF]\nHTTP Flood']
    scores = [9.8, 8.1, 8.1, 7.5, 7.5, 7.5]
    colors = [RED, ORANGE, ORANGE, CYAN, CYAN, CYAN]

    fig, ax = plt.subplots(figsize=(11, 5))
    fig.patch.set_facecolor(BG)

    bars = ax.barh(labels[::-1], scores[::-1], color=colors[::-1],
                   height=0.55, zorder=3, edgecolor='none')

    for bar, score in zip(bars, scores[::-1]):
        ax.text(bar.get_width() + 0.08, bar.get_y() + bar.get_height() / 2,
                f'{score}', va='center', ha='left',
                fontsize=12, fontweight='bold',
                color=bar.get_facecolor())

    ax.set_xlim(0, 11.5)
    ax.set_xlabel('CVSS v3.1 Score', fontsize=10)
    ax.set_title('⊕  CRASHBANDICOOT  —  CVSS Score по уязвимостям  ⊕',
                 fontsize=13, fontweight='bold', color='#e0e0e0', pad=14)
    ax.axvline(x=9.0, color=RED,    linestyle=':', alpha=0.5, lw=1)
    ax.axvline(x=7.0, color=ORANGE, linestyle=':', alpha=0.5, lw=1)
    ax.text(9.02, 0.02, 'Critical', color=RED,    fontsize=8, alpha=0.7,
            transform=ax.get_xaxis_transform())
    ax.text(7.02, 0.02, 'High',     color=ORANGE, fontsize=8, alpha=0.7,
            transform=ax.get_xaxis_transform())
    ax.grid(axis='x', zorder=0)
    ax.tick_params(axis='y', labelsize=10)

    legend = [mpatches.Patch(color=RED,    label='Critical (9.0+)'),
              mpatches.Patch(color=ORANGE, label='High (8.0–8.9)'),
              mpatches.Patch(color=CYAN,   label='High (7.0–7.9)')]
    ax.legend(handles=legend, loc='lower right', fontsize=9,
              facecolor=PANEL, edgecolor=GREY, labelcolor='#e0e0e0')

    plt.tight_layout()
    path = os.path.join(OUT, '01_cvss_scores.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'  ✓ {path}')


# ─────────────────────────────────────────────────────────────────────────────
# 2. Timing oracle — recovery timeline
# ─────────────────────────────────────────────────────────────────────────────
def graph_timing():
    fig, ax = plt.subplots(figsize=(11, 4))
    fig.patch.set_facecolor(BG)

    ax.set_xlim(0, 110)
    ax.set_ylim(0, 1)
    ax.axis('off')
    ax.set_title('⊕  TIMING ORACLE  —  Recovery Time по типу краша  ⊕',
                 fontsize=13, fontweight='bold', color='#e0e0e0', pad=14)

    segments = [
        (0, 2.5,  GREEN,  'HIT\nUser-space crash\n~2.5s'),
        (0, 9.7,  CYAN,   'HIT\nHeap corruption\n~9.7s'),
        (0, 20,   YELLOW, 'DEAD\nShellcode loop\n>20s  →  RCE!'),
        (0, 90,   RED,    'PANIC\nKernel panic\n>90s'),
    ]

    y_pos = [0.72, 0.52, 0.32, 0.12]
    for (x0, x1, color, label), y in zip(segments, y_pos):
        # bar
        ax.barh(y, x1, left=x0, height=0.13, color=color,
                alpha=0.85, zorder=3)
        # label left
        tag = label.split('\n')[0]
        ax.text(-1, y, tag, va='center', ha='right',
                fontsize=9, color=color, fontweight='bold')
        # time marker
        ax.text(x1 + 1, y, f'{x1}s', va='center', ha='left',
                fontsize=10, color=color, fontweight='bold')
        # desc
        desc = label.split('\n')[1]
        ax.text(x1 / 2, y, desc, va='center', ha='center',
                fontsize=8, color=BG, fontweight='bold', zorder=5)

    # DEAD zone highlight
    ax.axvspan(20, 110, alpha=0.04, color=YELLOW, zorder=0)
    ax.text(65, 0.92, '← RCE ZONE (no restart)', color=YELLOW,
            fontsize=9, alpha=0.6, ha='center')

    plt.tight_layout()
    path = os.path.join(OUT, '02_timing_oracle.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'  ✓ {path}')


# ─────────────────────────────────────────────────────────────────────────────
# 3. Stack layout
# ─────────────────────────────────────────────────────────────────────────────
def graph_stack():
    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.axis('off')
    ax.set_title('⊕  STACK LAYOUT  —  User-Agent overflow (252 bytes)  ⊕',
                 fontsize=13, fontweight='bold', color='#e0e0e0', pad=14)

    total = 252
    segments = [
        (0,   102, GREEN,  '[0–101]\nua_buf\n102 bytes\nshellcode here'),
        (102, 114, CYAN,   '[102–215]\nlocals\n114 bytes\nfiller B×114'),
        (216, 32,  ORANGE, '[216–247]\nR4–R11\n32 bytes\nARM_NOP×8'),
        (248, 4,   RED,    '[248–251]\nsaved PC\n4 bytes\n← control here'),
    ]

    bar_y = 0.55
    bar_h = 0.28

    for start, size, color, label in segments:
        x      = start / total
        width  = size  / total
        rect   = FancyBboxPatch((x + 0.002, bar_y), width - 0.004, bar_h,
                                boxstyle='round,pad=0.005',
                                facecolor=color, alpha=0.85,
                                edgecolor=BG, linewidth=2)
        ax.add_patch(rect)
        lines = label.split('\n')
        ax.text(x + width / 2, bar_y + bar_h / 2 + 0.04,
                lines[0], ha='center', va='center',
                fontsize=9, fontweight='bold', color=BG)
        ax.text(x + width / 2, bar_y + bar_h / 2 - 0.04,
                lines[1], ha='center', va='center',
                fontsize=8, color=BG)
        # size label below
        ax.text(x + width / 2, bar_y - 0.07,
                lines[2], ha='center', va='top',
                fontsize=8, color=color)
        # annotation below
        ax.text(x + width / 2, bar_y - 0.17,
                lines[3], ha='center', va='top',
                fontsize=8, color=LGREY)

    # Arrow on PC
    pc_x = 248 / total + (4 / total) / 2
    ax.annotate('', xy=(pc_x, bar_y + bar_h + 0.05),
                xytext=(pc_x, bar_y + bar_h + 0.18),
                arrowprops=dict(arrowstyle='->', color=RED, lw=2))
    ax.text(pc_x, bar_y + bar_h + 0.22,
            'BX R0 gadget addr\n(null-free, 4-aligned)',
            ha='center', va='bottom', fontsize=9, color=RED)

    # offset axis
    for start, size, color, _ in segments:
        ax.text(start / total, bar_y - 0.02, str(start),
                ha='center', va='bottom', fontsize=7, color=LGREY)
    ax.text(252 / total, bar_y - 0.02, '252',
            ha='center', va='bottom', fontsize=7, color=LGREY)

    ax.set_xlim(-0.02, 1.08)
    ax.set_ylim(0, 1.1)

    # null-free note
    ax.text(0.5, 0.02,
            '⚠  strcpy() stops at 0x00  →  every byte must be non-zero',
            ha='center', va='bottom', fontsize=9,
            color=YELLOW, alpha=0.8)

    plt.tight_layout()
    path = os.path.join(OUT, '03_stack_layout.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'  ✓ {path}')


# ─────────────────────────────────────────────────────────────────────────────
# 4. BX R0 scan progress
# ─────────────────────────────────────────────────────────────────────────────
def graph_scan():
    fig, ax = plt.subplots(figsize=(11, 4.5))
    fig.patch.set_facecolor(BG)

    total      = 938
    scanned    = 117
    remaining  = total - scanned

    # radial / donut
    ax.axis('off')
    ax2 = fig.add_axes([0.04, 0.1, 0.38, 0.8])
    ax2.set_facecolor(BG)
    ax2.axis('equal')

    wedge_colors = [GREEN, GREY]
    wedge_data   = [scanned, remaining]
    wedges, _ = ax2.pie(wedge_data, colors=wedge_colors,
                        startangle=90, counterclock=False,
                        wedgeprops=dict(width=0.45, edgecolor=BG, linewidth=2))
    ax2.text(0, 0.12, f'{scanned}', ha='center', va='center',
             fontsize=28, fontweight='bold', color=GREEN)
    ax2.text(0, -0.22, f'/ {total}', ha='center', va='center',
             fontsize=14, color=LGREY)
    ax2.text(0, -0.48, 'кандидатов\nпроверено', ha='center', va='center',
             fontsize=10, color=LGREY)
    ax2.set_title('BX R0 Gadget Scan', fontsize=11, color='#e0e0e0', pad=8)

    # right: stats table
    ax3 = fig.add_axes([0.46, 0.05, 0.52, 0.9])
    ax3.set_facecolor(BG)
    ax3.axis('off')
    ax3.set_title('⊕  SCAN PROGRESS  —  mmap 0x40000000–0x40F30000  ⊕',
                  fontsize=12, fontweight='bold', color='#e0e0e0', pad=10)

    stats = [
        ('Регион',         '0x40000000 – 0x40F30000', LGREY),
        ('Размер',         '~15 MB',                   LGREY),
        ('Шаг (step)',     '0x1001 (≈4 KB)',            LGREY),
        ('Всего кандидатов','938',                      CYAN),
        ('Проверено',      f'{scanned} ({scanned/total*100:.1f}%)', GREEN),
        ('Осталось',       f'{remaining} ({remaining/total*100:.1f}%)', ORANGE),
        ('HIT найдено',    f'{scanned} (все)',          GREEN),
        ('DEAD (RCE)',      '0',                        RED),
        ('Гаджет BX R0',   'не найден',                RED),
        ('Гаджет BLX R0',  'не проверялся',            LGREY),
    ]

    for i, (key, val, color) in enumerate(stats):
        y = 0.88 - i * 0.09
        ax3.text(0.0, y, key, fontsize=10, color=LGREY, va='center')
        ax3.text(0.55, y, val, fontsize=10, color=color,
                 va='center', fontweight='bold')

    ax3.set_xlim(0, 1.1)
    ax3.set_ylim(0, 1)

    plt.tight_layout()
    path = os.path.join(OUT, '04_bxr0_scan.png')
    plt.savefig(path, dpi=150, bbox_inches='tight', facecolor=BG)
    plt.close()
    print(f'  ✓ {path}')


if __name__ == '__main__':
    print('Generating graphs...')
    graph_cvss()
    graph_timing()
    graph_stack()
    graph_scan()
    print('Done →', OUT)
