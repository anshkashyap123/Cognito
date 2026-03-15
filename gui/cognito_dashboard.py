# gui/cognito_dashboard.py  –  COGNITO XDR v3.0
# Premium military-grade dashboard with 6 full pages and advanced widgets

import platform, time, json, os
from PyQt5.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QGridLayout,
    QFrame, QLabel, QPushButton, QStackedWidget,
    QTableWidget, QTableWidgetItem, QListWidget, QListWidgetItem,
    QTextEdit, QSizePolicy, QHeaderView, QAbstractItemView,
    QLineEdit, QComboBox, QSpacerItem, QProgressBar,
    QSplitter, QScrollArea, QDialog, QDialogButtonBox,
    QMessageBox, QTabWidget, QGroupBox, QCheckBox
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QLinearGradient, QFont, QPen, QIcon, QBrush

from core.cognito_sniffer  import CognitoSniffer
from core.threat_engine    import ThreatEngine
from core.system_monitor   import SystemMonitor
from core.firewall         import detect_platform

from gui.graph_widget import RateGraph, ProtoDonut, ThreatTimeline, ResourceGraph
from gui import theme as T


# ── Utility: section label ────────────────────────────────────────────────────

def section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{T.TEXT}; font-size:15px; font-family:{T.MONO}; "
        f"font-weight:bold; letter-spacing:3px; padding-bottom:2px;"
    )
    return lbl


def sub_label(text: str, color=T.TEXT_DIM) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{color}; font-size:10px; font-family:{T.MONO}; "
        f"letter-spacing:2px;"
    )
    return lbl


def sep() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.HLine)
    line.setStyleSheet(f"color:{T.BORDER}; background:{T.BORDER}; max-height:1px;")
    return line


# ── Pulsing status dot ────────────────────────────────────────────────────────

class StatusDot(QWidget):
    def __init__(self, size=12):
        super().__init__()
        self.setFixedSize(size, size)
        self._active = False
        self._blink  = True
        self._color  = T.CYAN
        t = QTimer(self)
        t.timeout.connect(self._toggle)
        t.start(650)

    def set_active(self, v: bool, color=T.CYAN):
        self._active = v
        self._color  = color
        self.update()

    def _toggle(self):
        if self._active:
            self._blink = not self._blink
            self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = self.width()
        if self._active and self._blink:
            glow = QColor(self._color)
            glow.setAlpha(40)
            p.setBrush(QBrush(glow))
            p.setPen(Qt.NoPen)
            p.drawEllipse(0, 0, s, s)
            p.setBrush(QColor(self._color))
            p.drawEllipse(2, 2, s-4, s-4)
        elif self._active:
            dark = QColor(self._color)
            dark.setAlpha(100)
            p.setBrush(dark)
            p.setPen(Qt.NoPen)
            p.drawEllipse(2, 2, s-4, s-4)
        else:
            p.setBrush(QColor(T.TEXT_DIM))
            p.setPen(Qt.NoPen)
            p.drawEllipse(2, 2, s-4, s-4)


# ── Stat card ─────────────────────────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, title: str, value: str = "0", accent: str = T.CYAN,
                 icon: str = "", subtitle: str = ""):
        super().__init__()
        self._accent = accent
        self._title  = title
        self.setFixedHeight(110)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyleSheet(f"""
            QFrame {{
                background: {T.BG3};
                border: 1px solid {T.BORDER};
                border-left: 3px solid {accent};
                border-radius: 8px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 10)
        lay.setSpacing(2)

        top = QHBoxLayout()
        title_lbl = QLabel((icon + "  " if icon else "") + title.upper())
        title_lbl.setStyleSheet(
            f"color:{T.TEXT_DIM}; font-size:9px; font-family:{T.MONO}; "
            f"font-weight:bold; letter-spacing:2.5px; border:none; background:transparent;"
        )
        top.addWidget(title_lbl)
        top.addStretch()
        lay.addLayout(top)

        self._val = QLabel(value)
        self._val.setStyleSheet(
            f"color:{accent}; font-size:30px; font-family:{T.MONO}; "
            f"font-weight:bold; border:none; background:transparent;"
        )
        lay.addWidget(self._val)

        if subtitle:
            self._sub = QLabel(subtitle)
            self._sub.setStyleSheet(
                f"color:{T.TEXT_DIM}; font-size:9px; font-family:{T.MONO}; "
                f"border:none; background:transparent;"
            )
            lay.addWidget(self._sub)
        else:
            self._sub = None
        lay.addStretch()

    def set_value(self, v, color=None):
        self._val.setText(str(v))
        if color:
            self._val.setStyleSheet(
                self._val.styleSheet().split("color:")[0] +
                f"color:{color}; font-size:30px; font-family:{T.MONO}; "
                f"font-weight:bold; border:none; background:transparent;"
            )

    def set_sub(self, v):
        if self._sub:
            self._sub.setText(str(v))


# ── Animated progress bar ─────────────────────────────────────────────────────

class GlowBar(QProgressBar):
    def __init__(self, color=T.CYAN, height=6):
        super().__init__()
        self.setTextVisible(False)
        self.setFixedHeight(height)
        self.setStyleSheet(f"""
            QProgressBar {{
                background: {T.BORDER};
                border: none;
                border-radius: {height//2}px;
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {color}AA, stop:1 {color});
                border-radius: {height//2}px;
            }}
        """)


# ── Score ring widget ─────────────────────────────────────────────────────────

class ScoreRing(QWidget):
    def __init__(self):
        super().__init__()
        self.setFixedSize(130, 130)
        self._score = 100

    def set_score(self, v: int):
        self._score = max(0, min(100, v))
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setRenderHint(QPainter.TextAntialiasing)

        w, h = self.width(), self.height()
        margin = 12
        rect_size = w - 2 * margin

        # Background ring
        p.setPen(QPen(QColor(T.BORDER), 10, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(margin, margin, rect_size, rect_size, 0, 360*16)

        # Score arc
        score_color = (T.GREEN if self._score >= 70 else
                       T.ORANGE if self._score >= 40 else T.RED)
        angle = int(self._score / 100.0 * 360 * 16)
        p.setPen(QPen(QColor(score_color), 10, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(margin, margin, rect_size, rect_size, 90 * 16, -angle)

        # Center text
        p.setPen(QColor(score_color))
        font = QFont("Consolas", 22)
        font.setBold(True)
        p.setFont(font)
        p.drawText(0, 0, w, h - 12, Qt.AlignCenter, str(self._score))

        p.setPen(QColor(T.TEXT_DIM))
        font2 = QFont("Consolas", 8)
        p.setFont(font2)
        p.drawText(0, h // 2 + 18, w, 20, Qt.AlignCenter, "SECURITY SCORE")


# ── Navigation items ──────────────────────────────────────────────────────────

NAV = [
    ("⬡", "DASHBOARD",    0),
    ("⚠", "THREATS",      1),
    ("⊘", "BLOCKED IPs",  2),
    ("⊞", "ANALYTICS",    3),
    ("⌁", "SYSTEM",       4),
    ("≡", "LOGS",         5),
    ("⚙", "SETTINGS",     6),
]


class NavBtn(QPushButton):
    def __init__(self, icon, label):
        super().__init__(f"  {icon}  {label}")
        self.setCheckable(True)
        self.setFixedHeight(48)
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                color: {T.TEXT_DIM};
                background: transparent;
                border: none;
                border-left: 3px solid transparent;
                padding: 0 20px;
                text-align: left;
                font-size: 11px;
                font-family: {T.MONO};
                letter-spacing: 1.5px;
            }}
            QPushButton:hover {{
                color: {T.TEXT};
                background: #06111F;
                border-left-color: {T.BORDER2};
            }}
            QPushButton:checked {{
                color: {T.CYAN};
                background: #071520;
                border-left-color: {T.CYAN};
                font-weight: bold;
            }}
        """)


# ── Sidebar ───────────────────────────────────────────────────────────────────

class Sidebar(QFrame):
    def __init__(self, dashboard):
        super().__init__()
        self.dash = dashboard
        self.setFixedWidth(T.SIDEBAR_W)
        self.setStyleSheet(f"""
            QFrame {{
                background: {T.SIDEBAR_BG};
                border-right: 1px solid {T.BORDER};
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Logo area ──────────────────────────────────────────────────────
        logo_frame = QFrame()
        logo_frame.setFixedHeight(76)
        logo_frame.setStyleSheet(f"border-bottom: 1px solid {T.BORDER};")
        ll = QHBoxLayout(logo_frame)
        ll.setContentsMargins(20, 0, 16, 0)

        self.dot = StatusDot(14)
        text_v = QVBoxLayout()
        text_v.setSpacing(1)
        logo_lbl = QLabel("COGNITO")
        logo_lbl.setStyleSheet(
            f"color:{T.CYAN}; font-size:22px; font-weight:bold; "
            f"font-family:{T.MONO}; letter-spacing:5px; border:none;"
        )
        xdr_lbl = QLabel("EXTENDED DETECTION & RESPONSE  v3.0")
        xdr_lbl.setStyleSheet(
            f"color:{T.TEXT_DIM}; font-size:7.5px; font-family:{T.MONO}; "
            f"letter-spacing:1px; border:none;"
        )
        text_v.addWidget(logo_lbl)
        text_v.addWidget(xdr_lbl)
        ll.addLayout(text_v)
        ll.addWidget(self.dot)
        lay.addWidget(logo_frame)

        # ── Platform badge ─────────────────────────────────────────────────
        pf = detect_platform()
        pfm_lbl = QLabel(f"  {pf['os'].upper()}  ·  {pf['arch']}")
        pfm_lbl.setStyleSheet(
            f"color:{T.TEXT_DIM}; font-size:8px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding:8px 20px 6px; border:none;"
        )
        lay.addWidget(pfm_lbl)
        lay.addWidget(sep())
        lay.addSpacing(8)

        # ── Nav buttons ────────────────────────────────────────────────────
        self._btns = []
        for icon, label, idx in NAV:
            btn = NavBtn(icon, label)
            btn.clicked.connect(lambda _, i=idx: self._nav(i))
            lay.addWidget(btn)
            self._btns.append(btn)
        self._btns[0].setChecked(True)

        lay.addStretch()
        lay.addWidget(sep())

        # ── Intel status ───────────────────────────────────────────────────
        self.intel_lbl = QLabel("  ⬤  THREAT INTEL: LOADING")
        self.intel_lbl.setStyleSheet(
            f"color:{T.TEXT_DIM}; font-size:8px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding:10px 0; border:none;"
        )
        lay.addWidget(self.intel_lbl)

        ver = QLabel("  COGNITO XDR v3.0  ·  ALPHA BUILD")
        ver.setStyleSheet(
            f"color:{T.TEXT_DIM}; font-size:8px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding:6px 0 12px; border:none;"
        )
        lay.addWidget(ver)

    def _nav(self, idx):
        for i, b in enumerate(self._btns):
            b.setChecked(i == idx)
        self.dash.stack.setCurrentIndex(idx)

    def set_running(self, v: bool):
        self.dot.set_active(v, T.CYAN if v else T.RED)

    def set_intel(self, count: int):
        color = T.GREEN if count > 0 else T.TEXT_DIM
        self.intel_lbl.setText(f"  ⬤  THREAT INTEL: {count:,} IPs")
        self.intel_lbl.setStyleSheet(
            f"color:{color}; font-size:8px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding:10px 0; border:none;"
        )


# ── Make button helper ────────────────────────────────────────────────────────

def make_btn(text, bg=T.CYAN, fg="#000", width=None, height=38) -> QPushButton:
    btn = QPushButton(text)
    btn.setFixedHeight(height)
    if width:
        btn.setFixedWidth(width)
    btn.setCursor(Qt.PointingHandCursor)
    btn.setStyleSheet(f"""
        QPushButton {{
            background: {bg};
            color: {fg};
            border: none;
            border-radius: 6px;
            padding: 0 18px;
            font-size: 11px;
            font-family: {T.MONO};
            font-weight: bold;
            letter-spacing: 1.5px;
        }}
        QPushButton:hover {{
            background: {bg}CC;
        }}
        QPushButton:pressed {{
            background: {bg}88;
        }}
        QPushButton:disabled {{
            background: {T.BORDER};
            color: {T.TEXT_DIM};
        }}
    """)
    return btn


# ── Panel frame helper ────────────────────────────────────────────────────────

def panel(title="", accent=T.BORDER) -> tuple:
    """Returns (outer_frame, inner_layout)"""
    frame = QFrame()
    frame.setStyleSheet(f"""
        QFrame {{
            background: {T.PANEL};
            border: 1px solid {T.BORDER};
            border-radius: 8px;
        }}
    """)
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(14, 12, 14, 12)
    lay.setSpacing(8)
    if title:
        lbl = sub_label(title)
        lay.addWidget(lbl)
    return frame, lay


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════

class CognitoDashboard(QWidget):

    def __init__(self):
        super().__init__()
        self.sniffer = CognitoSniffer()
        self.engine  = ThreatEngine()
        self.sysmon  = SystemMonitor()

        self.sniffer.add_callback(self.engine.process)
        self.engine.add_callback(self._on_threat)

        self._init_ui()

        # Timers
        self._ui_timer = QTimer(self)
        self._ui_timer.timeout.connect(self._refresh_ui)
        self._ui_timer.start(500)

        self._timeline_timer = QTimer(self)
        self._timeline_timer.timeout.connect(self._threat_timeline.tick)
        self._timeline_timer.start(5000)

        self._intel_timer = QTimer(self)
        self._intel_timer.timeout.connect(self._update_intel_badge)
        self._intel_timer.start(3000)

    # ── UI Bootstrap ─────────────────────────────────────────────────────────

    def _init_ui(self):
        self.setWindowTitle("COGNITO  ·  Military-Grade XDR v3.0")
        self.resize(1600, 940)
        self.setMinimumSize(1200, 750)
        self.setStyleSheet(f"""
            QWidget {{
                background: {T.BG};
                color: {T.TEXT};
                font-family: {T.SANS};
            }}
            QToolTip {{
                background: {T.PANEL};
                color: {T.TEXT};
                border: 1px solid {T.BORDER2};
                font-family: {T.MONO};
                font-size: 11px;
            }}
        """)

        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.sidebar = Sidebar(self)

        self.stack = QStackedWidget()
        self.stack.addWidget(self._page_dashboard())   # 0
        self.stack.addWidget(self._page_threats())     # 1
        self.stack.addWidget(self._page_blocked())     # 2
        self.stack.addWidget(self._page_analytics())   # 3
        self.stack.addWidget(self._page_system())      # 4
        self.stack.addWidget(self._page_logs())        # 5
        self.stack.addWidget(self._page_settings())    # 6

        root.addWidget(self.sidebar)
        root.addWidget(self.stack, stretch=1)

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 0: DASHBOARD
    # ════════════════════════════════════════════════════════════════════════

    def _page_dashboard(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(14)

        # ── Top bar ────────────────────────────────────────────────────────
        top = QHBoxLayout()
        top.addWidget(section_label("NETWORK OVERVIEW"))
        top.addStretch()

        self._mode_lbl = QLabel("⬤  DEMO MODE — No admin privileges needed")
        self._mode_lbl.setStyleSheet(
            f"color:{T.YELLOW}; font-size:9px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding-right:16px;"
        )
        top.addWidget(self._mode_lbl)

        self._start_btn = make_btn("▶  START PROTECTION", T.CYAN, "#000")
        self._stop_btn  = make_btn("■  STOP",             T.RED,  "#fff")
        self._stop_btn.setEnabled(False)
        self._start_btn.clicked.connect(self._start)
        self._stop_btn.clicked.connect(self._stop)
        top.addWidget(self._start_btn)
        top.addSpacing(8)
        top.addWidget(self._stop_btn)
        lay.addLayout(top)

        # ── Stat cards row ─────────────────────────────────────────────────
        cards = QHBoxLayout()
        cards.setSpacing(10)
        self._c_status  = StatCard("Status",        "IDLE",     T.TEXT_DIM)
        self._c_packets = StatCard("Packets",        "0",        T.CYAN,   icon="◈")
        self._c_rate    = StatCard("Packets / s",    "0",        T.BLUE,   icon="↯")
        self._c_bw      = StatCard("Bandwidth",      "0 B/s",    "#7DD3FC", icon="↕")
        self._c_threats = StatCard("Threats",        "0",        T.RED,    icon="⚠")
        self._c_blocked = StatCard("Blocked IPs",    "0",        T.ORANGE, icon="⊘")
        self._c_conns   = StatCard("Active Conns",   "0",        T.PURPLE, icon="⇄")

        for c in [self._c_status, self._c_packets, self._c_rate, self._c_bw,
                  self._c_threats, self._c_blocked, self._c_conns]:
            cards.addWidget(c)
        lay.addLayout(cards)

        # ── Middle: score ring + graphs ────────────────────────────────────
        mid = QHBoxLayout()
        mid.setSpacing(14)

        # Score + proto donut column
        left_col = QVBoxLayout()
        left_col.setSpacing(12)

        score_frame, score_lay = panel("SECURITY SCORE")
        score_frame.setFixedWidth(280)
        score_inner = QHBoxLayout()
        self._score_ring = ScoreRing()
        score_inner.addWidget(self._score_ring, alignment=Qt.AlignCenter)

        score_right = QVBoxLayout()
        score_right.setSpacing(6)
        self._sev_bars = {}
        for sev, col in T.SEV_COLORS.items():
            row = QHBoxLayout()
            lbl = QLabel(sev)
            lbl.setFixedWidth(62)
            lbl.setStyleSheet(f"color:{col}; font-size:9px; font-family:{T.MONO}; font-weight:bold;")
            bar = GlowBar(col, 6)
            bar.setRange(0, 100)
            bar.setValue(0)
            cnt = QLabel("0")
            cnt.setFixedWidth(28)
            cnt.setStyleSheet(f"color:{T.TEXT_DIM}; font-size:9px; font-family:{T.MONO};")
            row.addWidget(lbl)
            row.addWidget(bar)
            row.addWidget(cnt)
            score_right.addLayout(row)
            self._sev_bars[sev] = (bar, cnt)

        score_inner.addLayout(score_right)
        score_lay.addLayout(score_inner)
        left_col.addWidget(score_frame)

        # Protocol donut
        proto_frame, proto_lay = panel("PROTOCOL BREAKDOWN")
        proto_frame.setFixedWidth(280)
        self._proto_donut = ProtoDonut()
        proto_lay.addWidget(self._proto_donut)
        left_col.addWidget(proto_frame)
        left_col.addStretch()
        mid.addLayout(left_col)

        # Right: rate graph + threat timeline
        right_col = QVBoxLayout()
        right_col.setSpacing(12)

        rate_frame, rate_lay = panel("LIVE PACKET RATE  (60s window) ─── CYAN = pkt/s  ·  BLUE = KB/s")
        self._rate_graph = RateGraph()
        rate_lay.addWidget(self._rate_graph)
        right_col.addWidget(rate_frame, stretch=2)

        timeline_frame, timeline_lay = panel("THREAT ACTIVITY TIMELINE")
        self._threat_timeline = ThreatTimeline()
        timeline_lay.addWidget(self._threat_timeline)
        right_col.addWidget(timeline_frame, stretch=1)

        mid.addLayout(right_col, stretch=1)
        lay.addLayout(mid, stretch=1)

        # ── Recent threats strip ───────────────────────────────────────────
        recent_frame, recent_lay = panel("RECENT THREATS")
        recent_frame.setFixedHeight(140)
        self._recent_log = QTextEdit()
        self._recent_log.setReadOnly(True)
        self._recent_log.setStyleSheet(T.textedit_css())
        self._recent_log.setFixedHeight(100)
        recent_lay.addWidget(self._recent_log)
        lay.addWidget(recent_frame)

        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 1: THREATS
    # ════════════════════════════════════════════════════════════════════════

    def _page_threats(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(12)

        # Header + filter row
        hdr = QHBoxLayout()
        hdr.addWidget(section_label("THREAT EVENTS"))
        hdr.addStretch()

        self._thr_filter = QComboBox()
        self._thr_filter.addItems(["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._thr_filter.setStyleSheet(T.combo_css())
        self._thr_filter.setFixedWidth(160)
        self._thr_filter.currentTextChanged.connect(self._filter_threats)

        self._thr_search = QLineEdit()
        self._thr_search.setPlaceholderText("Search IP / threat type...")
        self._thr_search.setStyleSheet(T.input_css())
        self._thr_search.setFixedWidth(220)
        self._thr_search.textChanged.connect(self._filter_threats)

        clear_btn = make_btn("CLEAR", T.BORDER2, T.TEXT_DIM, width=70)
        clear_btn.clicked.connect(self._clear_threats)

        export_btn = make_btn("EXPORT JSON", T.BLUE_DIM, T.TEXT, width=110)
        export_btn.clicked.connect(self._export_threats)

        hdr.addWidget(self._thr_search)
        hdr.addSpacing(8)
        hdr.addWidget(self._thr_filter)
        hdr.addSpacing(8)
        hdr.addWidget(clear_btn)
        hdr.addSpacing(8)
        hdr.addWidget(export_btn)
        lay.addLayout(hdr)

        # Counters strip
        counts_row = QHBoxLayout()
        counts_row.setSpacing(8)
        self._sev_count_lbls = {}
        for sev, col in T.SEV_COLORS.items():
            fr = QFrame()
            fr.setStyleSheet(f"""
                QFrame {{
                    background: {T.SEV_BG.get(sev, T.BG2)};
                    border: 1px solid {col}44;
                    border-radius: 6px;
                    padding: 4px 12px;
                }}
            """)
            fl = QHBoxLayout(fr)
            fl.setContentsMargins(10, 4, 10, 4)
            fl.setSpacing(6)
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{col}; font-size:10px; border:none;")
            lbl = QLabel(f"{sev}  0")
            lbl.setStyleSheet(f"color:{col}; font-size:9px; font-family:{T.MONO}; font-weight:bold; border:none;")
            fl.addWidget(dot)
            fl.addWidget(lbl)
            counts_row.addWidget(fr)
            self._sev_count_lbls[sev] = lbl
        counts_row.addStretch()
        lay.addLayout(counts_row)

        # Threat table
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(9)
        self.threat_table.setHorizontalHeaderLabels(
            ["#", "TIME", "IP ADDRESS", "COUNTRY", "THREAT TYPE",
             "PROTOCOL", "PORT/SERVICE", "SEVERITY", "DETAILS"]
        )
        self.threat_table.setStyleSheet(T.table_css())
        self.threat_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.threat_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.threat_table.verticalHeader().setVisible(False)
        self.threat_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.threat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self.threat_table.setColumnWidth(0, 44)
        self.threat_table.setShowGrid(True)
        self.threat_table.setAlternatingRowColors(False)
        self.threat_table.setSortingEnabled(True)
        lay.addWidget(self.threat_table)

        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 2: BLOCKED IPs
    # ════════════════════════════════════════════════════════════════════════

    def _page_blocked(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(section_label("BLOCKED IP ADDRESSES"))
        hdr.addStretch()

        self._unblock_btn = make_btn("UNBLOCK SELECTED", T.ORANGE, "#000", width=160)
        self._unblock_btn.clicked.connect(self._unblock_selected)

        manual_btn = make_btn("BLOCK IP MANUALLY", T.RED, "#fff", width=155)
        manual_btn.clicked.connect(self._manual_block_dialog)

        hdr.addWidget(self._unblock_btn)
        hdr.addSpacing(8)
        hdr.addWidget(manual_btn)
        lay.addLayout(hdr)

        # Split: blocked list + whitelist panel
        split = QHBoxLayout()
        split.setSpacing(14)

        # Blocked table
        bl_frame, bl_lay = panel("BLOCKED IPs")
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(5)
        self.blocked_table.setHorizontalHeaderLabels(
            ["IP ADDRESS", "COUNTRY", "THREAT TYPE", "TIME BLOCKED", "STATUS"]
        )
        self.blocked_table.setStyleSheet(T.table_css())
        self.blocked_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.blocked_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.blocked_table.verticalHeader().setVisible(False)
        self.blocked_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        bl_lay.addWidget(self.blocked_table)
        split.addWidget(bl_frame, stretch=2)

        # Whitelist panel
        wl_frame, wl_lay = panel("WHITELIST (TRUSTED IPs)")
        wl_frame.setFixedWidth(300)

        self.wl_list = QListWidget()
        self.wl_list.setStyleSheet(T.list_css())

        wl_add_row = QHBoxLayout()
        self._wl_input = QLineEdit()
        self._wl_input.setPlaceholderText("Add IP to whitelist...")
        self._wl_input.setStyleSheet(T.input_css())
        wl_add_btn = make_btn("ADD", T.GREEN, "#000", width=55)
        wl_add_btn.clicked.connect(self._add_whitelist)
        wl_rem_btn = make_btn("REMOVE", T.RED_DIM, T.TEXT, width=70)
        wl_rem_btn.clicked.connect(self._remove_whitelist)
        wl_add_row.addWidget(self._wl_input)
        wl_add_row.addWidget(wl_add_btn)
        wl_add_row.addWidget(wl_rem_btn)

        wl_lay.addLayout(wl_add_row)
        wl_lay.addWidget(self.wl_list)
        split.addWidget(wl_frame)

        lay.addLayout(split)
        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 3: ANALYTICS
    # ════════════════════════════════════════════════════════════════════════

    def _page_analytics(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(14)
        lay.addWidget(section_label("TRAFFIC ANALYTICS"))

        # Top row: top IPs + top ports + top countries
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        ip_frame, ip_lay = panel("TOP SOURCE IPs")
        self._top_ips_list = QListWidget()
        self._top_ips_list.setStyleSheet(T.list_css())
        ip_lay.addWidget(self._top_ips_list)
        top_row.addWidget(ip_frame)

        port_frame, port_lay = panel("TOP DESTINATION PORTS")
        self._top_ports_list = QListWidget()
        self._top_ports_list.setStyleSheet(T.list_css())
        port_lay.addWidget(self._top_ports_list)
        top_row.addWidget(port_frame)

        country_frame, country_lay = panel("TOP COUNTRIES")
        self._top_countries_list = QListWidget()
        self._top_countries_list.setStyleSheet(T.list_css())
        country_lay.addWidget(self._top_countries_list)
        top_row.addWidget(country_frame)

        lay.addLayout(top_row, stretch=1)

        # Bottom row: threat types breakdown
        type_frame, type_lay = panel("THREAT TYPE DISTRIBUTION")
        type_frame.setFixedHeight(220)
        self._type_list = QListWidget()
        self._type_list.setStyleSheet(T.list_css())
        type_lay.addWidget(self._type_list)
        lay.addWidget(type_frame)

        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 4: SYSTEM MONITOR
    # ════════════════════════════════════════════════════════════════════════

    def _page_system(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(14)
        lay.addWidget(section_label("SYSTEM MONITOR"))

        # Metric cards row
        cards_row = QHBoxLayout()
        cards_row.setSpacing(10)
        self._c_cpu   = StatCard("CPU Usage",   "0%",   T.BLUE,   icon="◉")
        self._c_ram   = StatCard("RAM Usage",   "0%",   T.PURPLE, icon="▣")
        self._c_disk  = StatCard("Disk Usage",  "0%",   T.ORANGE, icon="⬡")
        self._c_ns    = StatCard("Net Sent",    "0 B/s",T.CYAN,   icon="↑")
        self._c_nr    = StatCard("Net Recv",    "0 B/s",T.GREEN,  icon="↓")
        for c in [self._c_cpu, self._c_ram, self._c_disk, self._c_ns, self._c_nr]:
            cards_row.addWidget(c)
        lay.addLayout(cards_row)

        # Resource graphs
        graphs_row = QHBoxLayout()
        graphs_row.setSpacing(12)

        cpu_frame, cpu_lay = panel("CPU & RAM HISTORY  (60s)")
        self._res_graph = ResourceGraph()
        cpu_lay.addWidget(self._res_graph)
        graphs_row.addWidget(cpu_frame, stretch=2)

        iface_frame, iface_lay = panel("NETWORK INTERFACES")
        iface_frame.setFixedWidth(280)
        self._iface_list = QListWidget()
        self._iface_list.setStyleSheet(T.list_css())
        iface_lay.addWidget(self._iface_list)
        graphs_row.addWidget(iface_frame)

        lay.addLayout(graphs_row, stretch=1)

        # ML stats
        ml_frame, ml_lay = panel("ML DETECTOR STATUS")
        ml_frame.setFixedHeight(140)
        self._ml_text = QTextEdit()
        self._ml_text.setReadOnly(True)
        self._ml_text.setStyleSheet(T.textedit_css())
        ml_lay.addWidget(self._ml_text)
        lay.addWidget(ml_frame)

        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 5: LOGS
    # ════════════════════════════════════════════════════════════════════════

    def _page_logs(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.addWidget(section_label("THREAT LOG"))
        hdr.addStretch()

        clear_btn  = make_btn("CLEAR",      T.BORDER2, T.TEXT_DIM, width=75)
        export_btn = make_btn("SAVE LOG",   T.BLUE_DIM, T.TEXT,    width=95)
        reload_btn = make_btn("RELOAD FILE",T.CYAN_DIM, T.CYAN,    width=110)

        clear_btn.clicked.connect(lambda: self.logs_box.clear())
        export_btn.clicked.connect(self._save_log_to_file)
        reload_btn.clicked.connect(self._reload_log_file)

        hdr.addWidget(clear_btn)
        hdr.addSpacing(8)
        hdr.addWidget(export_btn)
        hdr.addSpacing(8)
        hdr.addWidget(reload_btn)
        lay.addLayout(hdr)

        self.logs_box = QTextEdit()
        self.logs_box.setReadOnly(True)
        self.logs_box.setStyleSheet(T.textedit_css())
        lay.addWidget(self.logs_box)
        return page

    # ════════════════════════════════════════════════════════════════════════
    #  PAGE 6: SETTINGS
    # ════════════════════════════════════════════════════════════════════════

    def _page_settings(self):
        page = QWidget()
        lay  = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 16)
        lay.setSpacing(16)
        lay.addWidget(section_label("SETTINGS"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: transparent; }}")
        inner = QWidget()
        inner.setStyleSheet(f"background: transparent;")
        inner_lay = QVBoxLayout(inner)
        inner_lay.setSpacing(16)
        inner_lay.setContentsMargins(0, 0, 0, 0)

        # ── Detection thresholds ────────────────────────────────────────────
        det_frame, det_lay = panel("DETECTION THRESHOLDS")
        thresh_grid = QGridLayout()
        thresh_grid.setSpacing(10)
        thresh_grid.setColumnStretch(1, 1)

        def thresh_row(row, label, default_val, key):
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color:{T.TEXT}; font-size:12px; font-family:{T.MONO};")
            inp = QLineEdit(str(default_val))
            inp.setStyleSheet(T.input_css())
            inp.setFixedWidth(100)
            thresh_grid.addWidget(lbl, row, 0)
            thresh_grid.addWidget(inp, row, 1, alignment=Qt.AlignLeft)
            return inp

        from core.threat_engine import DDOS_TOTAL_THRESH, PORTSCAN_THRESH, BRUTE_THRESH
        self._thresh_ddos    = thresh_row(0, "DDoS Threshold (packets/IP)",  DDOS_TOTAL_THRESH, "ddos")
        self._thresh_portscan= thresh_row(1, "Port Scan Threshold (unique ports)", PORTSCAN_THRESH, "scan")
        self._thresh_brute   = thresh_row(2, "Brute Force Threshold (attempts)",   BRUTE_THRESH,   "brute")

        apply_btn = make_btn("APPLY THRESHOLDS", T.CYAN, "#000", width=180)
        apply_btn.clicked.connect(self._apply_thresholds)

        det_lay.addLayout(thresh_grid)
        det_lay.addSpacing(4)
        det_lay.addWidget(apply_btn, alignment=Qt.AlignLeft)
        inner_lay.addWidget(det_frame)

        # ── Options ─────────────────────────────────────────────────────────
        opt_frame, opt_lay = panel("RUNTIME OPTIONS")
        self._cb_autoblock  = QCheckBox("Auto-block on CRITICAL threats")
        self._cb_mldetect   = QCheckBox("Enable ML anomaly detection")
        self._cb_intel      = QCheckBox("Enable threat intelligence feeds")
        self._cb_sysmon     = QCheckBox("Enable system monitor")
        for cb in [self._cb_autoblock, self._cb_mldetect, self._cb_intel, self._cb_sysmon]:
            cb.setChecked(True)
            cb.setStyleSheet(f"color:{T.TEXT}; font-size:12px; font-family:{T.MONO}; spacing:8px;")
            opt_lay.addWidget(cb)
        inner_lay.addWidget(opt_frame)

        # ── Reset / danger zone ──────────────────────────────────────────────
        danger_frame, danger_lay = panel("DANGER ZONE")
        rst_score_btn  = make_btn("RESET SECURITY SCORE", T.ORANGE, "#000", width=200)
        clr_block_btn  = make_btn("UNBLOCK ALL IPs",       T.RED,    "#fff", width=160)
        clr_log_btn    = make_btn("CLEAR THREAT LOG",      T.RED_DIM, T.TEXT, width=160)
        rst_score_btn.clicked.connect(lambda: (self.engine.reset_score(), self._score_ring.set_score(100)))
        clr_block_btn.clicked.connect(self._unblock_all)
        clr_log_btn.clicked.connect(self._clear_log_file)

        danger_row = QHBoxLayout()
        danger_row.addWidget(rst_score_btn)
        danger_row.addSpacing(8)
        danger_row.addWidget(clr_block_btn)
        danger_row.addSpacing(8)
        danger_row.addWidget(clr_log_btn)
        danger_row.addStretch()
        danger_lay.addLayout(danger_row)
        inner_lay.addWidget(danger_frame)

        # ── Platform info ────────────────────────────────────────────────────
        pf_frame, pf_lay = panel("PLATFORM INFORMATION")
        pf = detect_platform()
        for k, v in pf.items():
            lbl = QLabel(f"{k.upper()}:  {v}")
            lbl.setStyleSheet(f"color:{T.TEXT_DIM}; font-size:11px; font-family:{T.MONO};")
            pf_lay.addWidget(lbl)
        inner_lay.addWidget(pf_frame)

        inner_lay.addStretch()
        scroll.setWidget(inner)
        lay.addWidget(scroll)
        return page

    # ════════════════════════════════════════════════════════════════════════
    #  REFRESH LOOP
    # ════════════════════════════════════════════════════════════════════════

    def _refresh_ui(self):
        s  = self.sniffer.get_stats()
        es = self.engine.get_stats()
        sm = self.sysmon.get_stats()

        bw_fmt = CognitoSniffer.format_bytes(s.get("bytes_rate", 0)) + "/s"

        # ── Stat cards ──────────────────────────────────────────────────────
        self._c_packets.set_value(f"{s['packets']:,}")
        self._c_rate.set_value(str(s['rate']))
        self._c_bw.set_value(bw_fmt)
        self._c_threats.set_value(str(es['total_threats']))
        self._c_blocked.set_value(str(es['total_blocked']))
        self._c_conns.set_value(str(s.get('active_conns', 0)))

        # ── Score ring + severity bars ───────────────────────────────────────
        score = es['security_score']
        self._score_ring.set_score(score)
        sev_total = max(es['total_threats'], 1)
        for sev, (bar, cnt_lbl) in self._sev_bars.items():
            cnt = es['sev_counts'].get(sev, 0)
            bar.setValue(int(cnt / sev_total * 100))
            cnt_lbl.setText(str(cnt))

        # ── Protocol donut ───────────────────────────────────────────────────
        self._proto_donut.update(s.get('proto_counts', {}))

        # ── Rate graph ────────────────────────────────────────────────────────
        self._rate_graph.update(s['rate'], s.get('bytes_rate', 0))

        # ── Severity counters on threats page ────────────────────────────────
        for sev, lbl in self._sev_count_lbls.items():
            cnt = es['sev_counts'].get(sev, 0)
            lbl.setText(f"{sev}  {cnt}")

        # ── Blocked table (full refresh every cycle) ──────────────────────────
        self._refresh_blocked_table(es)

        # ── Whitelist ─────────────────────────────────────────────────────────
        self._refresh_whitelist(es)

        # ── Analytics ────────────────────────────────────────────────────────
        self._refresh_analytics(s, es)

        # ── System page ───────────────────────────────────────────────────────
        self._c_cpu.set_value(f"{sm['cpu_pct']:.1f}%")
        self._c_ram.set_value(f"{sm['ram_pct']:.1f}%")
        self._c_disk.set_value(f"{sm.get('disk_pct', 0):.1f}%")
        self._c_ns.set_value(CognitoSniffer.format_bytes(sm['net_sent_bps']) + "/s")
        self._c_nr.set_value(CognitoSniffer.format_bytes(sm['net_recv_bps']) + "/s")
        self._res_graph.update(sm['cpu_pct'], sm['ram_pct'])

        ifaces = sm.get('net_ifaces', [])
        self._iface_list.clear()
        for iface in ifaces:
            item = QListWidgetItem(f"  {iface['name']}  —  {iface['ip']}")
            item.setForeground(QColor(T.CYAN))
            self._iface_list.addItem(item)

        ml_s = self.engine.ml.get_stats()
        self._ml_text.setHtml(
            f'<span style="color:{T.TEXT_DIM};font-family:Consolas;font-size:11px;">'
            f'<b style="color:{T.CYAN};">ML DETECTOR</b>  (IsolationForest + LOF Ensemble)<br>'
            f'Enabled: <span style="color:{T.GREEN if ml_s["enabled"] else T.RED};">'
            f'{"YES" if ml_s["enabled"] else "NO"}</span><br>'
            f'Total checks: <b style="color:{T.TEXT};">{ml_s["total_checks"]:,}</b><br>'
            f'Anomalies detected: <b style="color:{T.ORANGE};">{ml_s["anomaly_count"]:,}</b><br>'
            f'Retrains: {ml_s["retrain_count"]}<br>'
            f'Training samples: {ml_s["train_samples"]:,}'
            f'</span>'
        )

    def _refresh_blocked_table(self, es):
        blocked = es.get('blocked_ips', [])
        if self.blocked_table.rowCount() == len(blocked):
            return
        self.blocked_table.setRowCount(0)
        for ip in blocked:
            row = self.blocked_table.rowCount()
            self.blocked_table.insertRow(row)
            # Find matching threat event
            ev = next((e for e in es.get('threat_history', []) if e.get('ip') == ip), {})
            vals = [
                ip,
                ev.get('country_name', '—'),
                ev.get('threat', 'Manual Block'),
                ev.get('time', '—'),
                "BLOCKED",
            ]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                if c == 4:
                    item.setForeground(QColor(T.RED))
                    item.setFont(QFont("Consolas", 10, QFont.Bold))
                self.blocked_table.setItem(row, c, item)

    def _refresh_whitelist(self, es):
        wl = es.get('whitelist', [])
        self.wl_list.clear()
        for ip in wl:
            item = QListWidgetItem(f"  ✓  {ip}")
            item.setForeground(QColor(T.GREEN))
            self.wl_list.addItem(item)

    def _refresh_analytics(self, s, es):
        # Top IPs
        self._top_ips_list.clear()
        for i, (ip, cnt) in enumerate(s.get('top_ips', []), 1):
            item = QListWidgetItem(f"  {i:2d}.  {ip:<18}  {cnt:,} pkts")
            col = T.RED if cnt > 100 else T.TEXT
            item.setForeground(QColor(col))
            self._top_ips_list.addItem(item)

        # Top ports
        self._top_ports_list.clear()
        from core.cognito_sniffer import SERVICE_MAP
        for i, (port, cnt) in enumerate(s.get('top_ports', []), 1):
            svc = SERVICE_MAP.get(port, "UNKNOWN")
            item = QListWidgetItem(f"  {i:2d}.  :{port:<8} {svc:<12}  {cnt:,}")
            item.setForeground(QColor(T.BLUE))
            self._top_ports_list.addItem(item)

        # Top countries
        self._top_countries_list.clear()
        countries = sorted(s.get('country_counts', {}).items(), key=lambda x: x[1], reverse=True)[:10]
        for i, (cc, cnt) in enumerate(countries, 1):
            item = QListWidgetItem(f"  {i:2d}.  {cc}  —  {cnt:,} pkts")
            item.setForeground(QColor(T.PURPLE))
            self._top_countries_list.addItem(item)

        # Threat types
        self._type_list.clear()
        for threat_type, cnt in sorted(es.get('type_counts', {}).items(), key=lambda x: x[1], reverse=True):
            item = QListWidgetItem(f"  {threat_type:<38}  {cnt:,}")
            item.setForeground(QColor(T.ORANGE))
            self._type_list.addItem(item)

    def _update_intel_badge(self):
        cnt = self.engine.intel.count()
        self.sidebar.set_intel(cnt)

    # ════════════════════════════════════════════════════════════════════════
    #  THREAT EVENT HANDLER
    # ════════════════════════════════════════════════════════════════════════

    def _on_threat(self, event: dict):
        self._add_threat_row(event)
        self._add_log_line(event)
        self._threat_timeline.push(event.get("severity", "LOW"))
        self._add_recent_line(event)

    def _add_threat_row(self, ev: dict):
        sev   = ev.get("severity", "LOW")
        color = T.SEV_COLORS.get(sev, T.TEXT)
        bg    = T.SEV_BG.get(sev, T.BG2)

        row = self.threat_table.rowCount()
        self.threat_table.insertRow(row)

        details_str = ", ".join(f"{k}={v}" for k, v in ev.get("details", {}).items())
        svc = ev.get("service", "")
        port = ev.get("dst_port", "")
        port_svc = f"{port}/{svc}" if svc and svc != "UNKNOWN" else str(port)

        vals = [
            str(ev.get("id", row + 1)),
            ev.get("time", ""),
            ev.get("ip", ""),
            ev.get("country_name", ""),
            ev.get("threat", ""),
            ev.get("protocol", ""),
            port_svc,
            sev,
            details_str,
        ]
        for col, val in enumerate(vals):
            item = QTableWidgetItem(val)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 7:
                item.setForeground(QColor(color))
                f = item.font()
                f.setBold(True)
                item.setFont(f)
            elif col in (2, 4):
                item.setForeground(QColor(T.TEXT_BRIGHT))
            self.threat_table.setItem(row, col, item)

        if row % 2 == 0:
            for c in range(9):
                it = self.threat_table.item(row, c)
                if it:
                    it.setBackground(QBrush(QColor(T.BG2)))

        self.threat_table.scrollToBottom()

    def _add_log_line(self, ev: dict):
        sev   = ev.get("severity", "LOW")
        col   = T.SEV_COLORS.get(sev, T.TEXT)
        line = (
            f'<span style="color:{T.TEXT_DIM};font-family:Consolas;font-size:11px;">'
            f'[{ev.get("date","")} {ev.get("time","")}]</span>'
            f'&nbsp;<span style="color:{T.CYAN};font-family:Consolas;font-size:11px;">'
            f'{ev.get("ip","")}</span>'
            f'&nbsp;<span style="color:{T.TEXT_DIM};font-family:Consolas;">→</span>&nbsp;'
            f'<span style="color:{T.TEXT};font-family:Consolas;font-size:11px;">'
            f'{ev.get("threat","")}</span>'
            f'&nbsp;<span style="color:{col};font-family:Consolas;font-size:11px;font-weight:bold;">'
            f'[{sev}]</span>'
            f'&nbsp;<span style="color:{T.TEXT_DIM};font-family:Consolas;font-size:10px;">'
            f'{ev.get("country_name","")}</span>'
        )
        self.logs_box.append(line)

    def _add_recent_line(self, ev: dict):
        sev  = ev.get("severity", "LOW")
        col  = T.SEV_COLORS.get(sev, T.TEXT)
        line = (
            f'<span style="color:{col};font-family:Consolas;font-size:11px;font-weight:bold;">'
            f'[{sev}]</span>'
            f'&nbsp;<span style="color:{T.CYAN};font-family:Consolas;">{ev.get("ip","")}</span>'
            f'&nbsp;<span style="color:{T.TEXT};font-family:Consolas;font-size:11px;">'
            f'— {ev.get("threat","")}</span>'
        )
        self._recent_log.append(line)

    # ════════════════════════════════════════════════════════════════════════
    #  CONTROL SLOTS
    # ════════════════════════════════════════════════════════════════════════

    def _start(self):
        self.sniffer.start()
        self.sysmon.start()
        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self.sidebar.set_running(True)
        self._c_status.set_value("RUNNING", T.CYAN)
        self._mode_lbl.setText("⬤  LIVE — Protection active")
        self._mode_lbl.setStyleSheet(
            f"color:{T.GREEN}; font-size:9px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding-right:16px;"
        )

    def _stop(self):
        self.sniffer.stop()
        self.sysmon.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self.sidebar.set_running(False)
        self._c_status.set_value("STOPPED", T.RED)
        self._mode_lbl.setText("⬤  STOPPED")
        self._mode_lbl.setStyleSheet(
            f"color:{T.RED}; font-size:9px; font-family:{T.MONO}; "
            f"letter-spacing:1px; padding-right:16px;"
        )

    def _filter_threats(self):
        search = self._thr_search.text().lower()
        sev_filter = self._thr_filter.currentText()
        for row in range(self.threat_table.rowCount()):
            show = True
            sev_item = self.threat_table.item(row, 7)
            if sev_item and sev_filter != "All Severities":
                show = sev_item.text() == sev_filter
            if show and search:
                match = any(
                    (self.threat_table.item(row, c) or QTableWidgetItem("")).text().lower().find(search) >= 0
                    for c in range(9)
                )
                show = match
            self.threat_table.setRowHidden(row, not show)

    def _clear_threats(self):
        self.threat_table.setRowCount(0)

    def _export_threats(self):
        path = "logs/exported_threats.json"
        try:
            events = self.engine.get_stats().get('threat_history', [])
            with open(path, "w") as f:
                json.dump(events, f, indent=2)
            self._show_info(f"Exported {len(events)} events to {path}")
        except Exception as e:
            self._show_error(str(e))

    def _unblock_selected(self):
        rows = set(idx.row() for idx in self.blocked_table.selectedIndexes())
        for row in rows:
            item = self.blocked_table.item(row, 0)
            if item:
                self.engine.unblock(item.text())
        self.blocked_table.setRowCount(0)

    def _unblock_all(self):
        stats = self.engine.get_stats()
        for ip in stats.get('blocked_ips', []):
            self.engine.unblock(ip)
        self.blocked_table.setRowCount(0)

    def _manual_block_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Block IP Manually")
        dlg.setFixedSize(360, 140)
        dlg.setStyleSheet(f"background:{T.PANEL}; color:{T.TEXT}; font-family:{T.MONO};")
        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(20, 20, 20, 20)
        inp = QLineEdit()
        inp.setPlaceholderText("Enter IP address (e.g. 1.2.3.4)")
        inp.setStyleSheet(T.input_css())
        btns = QHBoxLayout()
        ok_btn  = make_btn("BLOCK",  T.RED, "#fff", width=90)
        cxl_btn = make_btn("CANCEL", T.BORDER2, T.TEXT, width=90)
        ok_btn.clicked.connect(lambda: (self.engine.manual_block(inp.text()), dlg.accept()))
        cxl_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addSpacing(8)
        btns.addWidget(cxl_btn)
        lay.addWidget(inp)
        lay.addSpacing(10)
        lay.addLayout(btns)
        dlg.exec_()

    def _add_whitelist(self):
        ip = self._wl_input.text().strip()
        if ip:
            self.engine.add_whitelist(ip)
            self._wl_input.clear()

    def _remove_whitelist(self):
        item = self.wl_list.currentItem()
        if item:
            ip = item.text().replace("  ✓  ", "").strip()
            self.engine.remove_whitelist(ip)

    def _apply_thresholds(self):
        import core.threat_engine as te
        try:
            te.DDOS_TOTAL_THRESH = int(self._thresh_ddos.text())
            te.PORTSCAN_THRESH   = int(self._thresh_portscan.text())
            te.BRUTE_THRESH      = int(self._thresh_brute.text())
            self._show_info("Thresholds updated successfully.")
        except ValueError as e:
            self._show_error(f"Invalid value: {e}")

    def _save_log_to_file(self):
        try:
            content = self.logs_box.toPlainText()
            with open("logs/cognito_session.log", "w") as f:
                f.write(content)
            self._show_info("Log saved to logs/cognito_session.log")
        except Exception as e:
            self._show_error(str(e))

    def _reload_log_file(self):
        try:
            if not os.path.exists("logs/threat_log.json"):
                return
            with open("logs/threat_log.json") as f:
                for line in f:
                    try:
                        ev = json.loads(line.strip())
                        self._add_log_line(ev)
                    except Exception:
                        pass
        except Exception as e:
            self._show_error(str(e))

    def _clear_log_file(self):
        try:
            open("logs/threat_log.json", "w").close()
            self._show_info("Threat log cleared.")
        except Exception as e:
            self._show_error(str(e))

    def _show_info(self, msg: str):
        mb = QMessageBox(self)
        mb.setWindowTitle("COGNITO")
        mb.setText(msg)
        mb.setStyleSheet(f"background:{T.PANEL}; color:{T.TEXT}; font-family:{T.MONO};")
        mb.exec_()

    def _show_error(self, msg: str):
        mb = QMessageBox(self)
        mb.setWindowTitle("Error")
        mb.setText(msg)
        mb.setIcon(QMessageBox.Warning)
        mb.setStyleSheet(f"background:{T.PANEL}; color:{T.TEXT}; font-family:{T.MONO};")
        mb.exec_()
