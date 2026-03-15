# gui/graph_widget.py  –  COGNITO XDR v3.0
# Multi-series matplotlib canvas: packet rate, bandwidth, protocol donut, threat timeline

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PyQt5.QtCore import Qt

from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
import matplotlib.ticker as ticker
import matplotlib.patches as mpatches
import numpy as np

from gui import theme as T


# ─── Base canvas ─────────────────────────────────────────────────────────────

class BaseCanvas(QWidget):
    def __init__(self, figsize=(6, 2.2), bg=T.PANEL):
        super().__init__()
        self.figure = Figure(figsize=figsize, facecolor=bg, tight_layout=True)
        self.canvas = FigureCanvasQTAgg(self.figure)
        self.canvas.setStyleSheet("background: transparent;")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self.canvas)

    def _style_ax(self, ax, title="", ylabel="", ylabelright=True):
        ax.set_facecolor(T.PANEL)
        ax.set_title(title, color=T.TEXT_DIM, fontsize=9, pad=5, fontfamily="monospace")
        for spine in ax.spines.values():
            spine.set_color(T.BORDER)
        ax.tick_params(colors=T.TEXT_DIM, labelsize=8, length=3)
        ax.xaxis.set_major_formatter(ticker.NullFormatter())
        if ylabelright:
            ax.yaxis.tick_right()
            ax.yaxis.set_label_position("right")
        ax.grid(True, color=T.BORDER, linewidth=0.5, linestyle="--", alpha=0.6)
        if ylabel:
            ax.set_ylabel(ylabel, color=T.TEXT_DIM, fontsize=8, fontfamily="monospace")


# ─── Packet rate + bandwidth dual-axis chart ──────────────────────────────────

class RateGraph(BaseCanvas):

    def __init__(self):
        super().__init__(figsize=(8, 2.4))
        self._pkt  = [0] * 60
        self._bw   = [0] * 60
        self._xs   = list(range(60))

        self.ax1 = self.figure.add_subplot(111)
        self.ax2 = self.ax1.twinx()

        self._style_ax(self.ax1, "", ylabelright=False)
        self.ax2.set_facecolor(T.PANEL)
        for spine in self.ax2.spines.values():
            spine.set_color(T.BORDER)
        self.ax2.tick_params(colors=T.TEXT_DIM, labelsize=8)
        self.ax2.grid(False)

        self._line1, = self.ax1.plot(self._xs, self._pkt, color=T.CYAN,    linewidth=1.8, zorder=4, label="pkt/s")
        self._line2, = self.ax2.plot(self._xs, self._bw,  color=T.BLUE,    linewidth=1.5, zorder=3, label="KB/s", alpha=0.8)
        self._fill1  = self.ax1.fill_between(self._xs, self._pkt, alpha=0.10, color=T.CYAN)
        self._fill2  = self.ax2.fill_between(self._xs, self._bw,  alpha=0.06, color=T.BLUE)

        self.canvas.draw()

    def update(self, pkt_rate: float, bw_bytes: float):
        self._pkt.append(pkt_rate)
        self._pkt.pop(0)
        self._bw.append(bw_bytes / 1024)
        self._bw.pop(0)

        self._line1.set_ydata(self._pkt)
        self._line2.set_ydata(self._bw)

        self._fill1.remove()
        self._fill2.remove()
        xs = self._xs
        self._fill1 = self.ax1.fill_between(xs, self._pkt, alpha=0.10, color=T.CYAN)
        self._fill2 = self.ax2.fill_between(xs, self._bw,  alpha=0.06, color=T.BLUE)

        top1 = max(self._pkt) or 10
        top2 = max(self._bw)  or 100
        self.ax1.set_ylim(0, top1 * 1.25)
        self.ax2.set_ylim(0, top2 * 1.25)

        self.canvas.draw_idle()


# ─── Protocol donut chart ─────────────────────────────────────────────────────

PROTO_PALETTE = {
    "TCP":   T.CYAN,
    "UDP":   T.BLUE,
    "ICMP":  T.YELLOW,
    "ARP":   T.PURPLE,
    "OTHER": T.TEXT_DIM,
}


class ProtoDonut(BaseCanvas):

    def __init__(self):
        super().__init__(figsize=(3.2, 2.6))
        self.ax = self.figure.add_subplot(111)
        self.ax.set_facecolor(T.PANEL)
        self.ax.axis("equal")
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        self.ax.set_facecolor(T.PANEL)
        self.ax.axis("equal")
        self.ax.pie(
            [1], colors=[T.BORDER],
            wedgeprops={"width": 0.45, "edgecolor": T.PANEL, "linewidth": 2},
            startangle=90
        )
        self.ax.text(0, 0, "NO DATA", ha="center", va="center",
                     color=T.TEXT_DIM, fontsize=8, fontfamily="monospace")
        self.canvas.draw_idle()

    def update(self, proto_counts: dict):
        if not proto_counts or sum(proto_counts.values()) == 0:
            self._draw_empty()
            return

        self.ax.clear()
        self.ax.set_facecolor(T.PANEL)
        self.ax.axis("equal")

        labels = list(proto_counts.keys())
        sizes  = list(proto_counts.values())
        colors = [PROTO_PALETTE.get(l, T.TEXT_DIM) for l in labels]

        wedges, _ = self.ax.pie(
            sizes, colors=colors,
            wedgeprops={"width": 0.48, "edgecolor": T.PANEL, "linewidth": 2},
            startangle=90
        )

        total = sum(sizes)
        self.ax.text(0, 0, f"{total:,}\nPKTS", ha="center", va="center",
                     color=T.TEXT, fontsize=8, fontfamily="monospace",
                     fontweight="bold", linespacing=1.6)
        self.canvas.draw_idle()


# ─── Severity timeline bar chart ─────────────────────────────────────────────

class ThreatTimeline(BaseCanvas):

    _BINS = 30   # 30 time buckets

    def __init__(self):
        super().__init__(figsize=(8, 1.8))
        self.ax = self.figure.add_subplot(111)
        self._style_ax(self.ax, "THREAT ACTIVITY")
        self._critical = [0] * self._BINS
        self._high      = [0] * self._BINS
        self._medium    = [0] * self._BINS
        self._low       = [0] * self._BINS
        self._draw()

    def push(self, severity: str):
        for arr, sev in [(self._critical, "CRITICAL"), (self._high, "HIGH"),
                         (self._medium, "MEDIUM"), (self._low, "LOW")]:
            if severity == sev:
                arr[-1] += 1
        self._draw()

    def tick(self):
        """Advance time bucket."""
        for arr in [self._critical, self._high, self._medium, self._low]:
            arr.append(0)
            arr.pop(0)

    def _draw(self):
        self.ax.clear()
        self._style_ax(self.ax)
        xs = list(range(self._BINS))
        b1 = self.ax.bar(xs, self._critical, color=T.RED,    alpha=0.85, width=0.8, label="CRITICAL")
        b2 = self.ax.bar(xs, self._high,     color=T.ORANGE, alpha=0.80, width=0.8,
                         bottom=self._critical, label="HIGH")
        bot3 = [c + h for c, h in zip(self._critical, self._high)]
        b3 = self.ax.bar(xs, self._medium,   color=T.YELLOW, alpha=0.75, width=0.8,
                         bottom=bot3, label="MEDIUM")
        bot4 = [b + m for b, m in zip(bot3, self._medium)]
        b4 = self.ax.bar(xs, self._low,      color=T.GREEN,  alpha=0.70, width=0.8,
                         bottom=bot4, label="LOW")

        self.ax.set_xlim(-0.5, self._BINS - 0.5)
        self.ax.set_facecolor(T.PANEL)
        for spine in self.ax.spines.values():
            spine.set_color(T.BORDER)
        self.ax.tick_params(colors=T.TEXT_DIM, labelsize=7, length=2)
        self.ax.xaxis.set_major_formatter(ticker.NullFormatter())
        self.ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True, nbins=3))
        self.ax.grid(axis="y", color=T.BORDER, linewidth=0.5, linestyle="--", alpha=0.5)
        self.canvas.draw_idle()


# ─── CPU / RAM resource bar ───────────────────────────────────────────────────

class ResourceGraph(BaseCanvas):

    def __init__(self):
        super().__init__(figsize=(5, 2.0))
        self._cpu = [0.0] * 60
        self._ram = [0.0] * 60
        self.ax   = self.figure.add_subplot(111)
        self._style_ax(self.ax, "SYSTEM RESOURCES")
        self._cpu_line, = self.ax.plot(self._cpu, color=T.BLUE,  linewidth=1.6, label="CPU%")
        self._ram_line, = self.ax.plot(self._ram, color=T.PURPLE, linewidth=1.6, label="RAM%", alpha=0.85)
        self._cpu_fill  = self.ax.fill_between(range(60), self._cpu, alpha=0.08, color=T.BLUE)
        self._ram_fill  = self.ax.fill_between(range(60), self._ram, alpha=0.06, color=T.PURPLE)
        self.ax.set_ylim(0, 105)
        self.canvas.draw()

    def update(self, cpu: float, ram: float):
        self._cpu.append(cpu)
        self._cpu.pop(0)
        self._ram.append(ram)
        self._ram.pop(0)

        self._cpu_line.set_ydata(self._cpu)
        self._ram_line.set_ydata(self._ram)
        self._cpu_fill.remove()
        self._ram_fill.remove()
        self._cpu_fill = self.ax.fill_between(range(60), self._cpu, alpha=0.08, color=T.BLUE)
        self._ram_fill = self.ax.fill_between(range(60), self._ram, alpha=0.06, color=T.PURPLE)
        self.canvas.draw_idle()
