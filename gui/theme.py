# gui/theme.py  –  COGNITO XDR v3.0
# Premium dark cyberpunk theme: deep navy + electric cyan + neon accents

# ── Core palette ──────────────────────────────────────────────────────────────
BG          = "#010B14"        # deepest background
BG2         = "#030F1C"        # panel background
BG3         = "#050F1E"        # card background
PANEL       = "#060D1A"        # elevated panel
BORDER      = "#0B1D33"        # border / divider
BORDER2     = "#0E2040"        # stronger border

# ── Accent colors ─────────────────────────────────────────────────────────────
CYAN        = "#00FFE7"        # primary accent — electric cyan
CYAN_DIM    = "#007060"        # dim cyan
CYAN_GLOW   = "#00FFE730"      # glow effect

BLUE        = "#1E90FF"        # secondary accent — dodger blue
BLUE_DIM    = "#1040A0"
BLUE_GLOW   = "#1E90FF25"

PURPLE      = "#9D4EDD"        # tertiary accent
PURPLE_GLOW = "#9D4EDD25"

# ── Status colors ─────────────────────────────────────────────────────────────
RED         = "#FF2D55"        # critical
RED_DIM     = "#801020"
RED_GLOW    = "#FF2D5530"

ORANGE      = "#FF9500"        # high severity
ORANGE_DIM  = "#804800"

YELLOW      = "#FFD60A"        # medium severity
YELLOW_DIM  = "#807000"

GREEN       = "#30D158"        # safe / low
GREEN_DIM   = "#1A7030"
GREEN_GLOW  = "#30D15825"

# ── Text ─────────────────────────────────────────────────────────────────────
TEXT        = "#C8D8F0"        # primary text
TEXT_DIM    = "#3A4A6A"        # muted text
TEXT_BRIGHT = "#E8F0FF"        # bright text

# ── Severity color map ────────────────────────────────────────────────────────
SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
}

SEV_BG = {
    "CRITICAL": "#200810",
    "HIGH":     "#201000",
    "MEDIUM":   "#1A1800",
    "LOW":      "#0A1810",
}

# ── Fonts ─────────────────────────────────────────────────────────────────────
MONO        = "Consolas, 'Cascadia Code', 'Fira Code', 'Courier New', monospace"
SANS        = "Segoe UI, 'SF Pro Display', Helvetica, Arial, sans-serif"

# ── Sidebar ───────────────────────────────────────────────────────────────────
SIDEBAR_W   = 220
SIDEBAR_BG  = "#020913"

# ── Scrollbar stylesheet ─────────────────────────────────────────────────────
SCROLLBAR_CSS = f"""
    QScrollBar:vertical {{
        background: {BG};
        width: 6px;
        margin: 0;
        border-radius: 3px;
    }}
    QScrollBar::handle:vertical {{
        background: {BORDER2};
        border-radius: 3px;
        min-height: 20px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {CYAN_DIM};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}
    QScrollBar:horizontal {{
        background: {BG};
        height: 6px;
        margin: 0;
        border-radius: 3px;
    }}
    QScrollBar::handle:horizontal {{
        background: {BORDER2};
        border-radius: 3px;
        min-width: 20px;
    }}
    QScrollBar::handle:horizontal:hover {{
        background: {CYAN_DIM};
    }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
        width: 0;
    }}
"""

# ── Table stylesheet ──────────────────────────────────────────────────────────
def table_css():
    return f"""
        QTableWidget {{
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 8px;
            gridline-color: {BORDER};
            color: {TEXT};
            font-family: {MONO};
            font-size: 12px;
            outline: none;
            selection-background-color: #0D2035;
        }}
        QHeaderView::section {{
            background: {BG2};
            color: {TEXT_DIM};
            font-family: {MONO};
            font-size: 10px;
            font-weight: bold;
            letter-spacing: 2px;
            padding: 10px 8px;
            border: none;
            border-bottom: 1px solid {BORDER2};
            border-right: 1px solid {BORDER};
        }}
        QHeaderView::section:last {{
            border-right: none;
        }}
        QTableWidget::item {{
            padding: 7px 10px;
            border-bottom: 1px solid {BORDER};
        }}
        QTableWidget::item:selected {{
            background: #0D2035;
            color: {CYAN};
        }}
        QTableWidget::item:hover {{
            background: #071525;
        }}
        {SCROLLBAR_CSS}
    """


def list_css():
    return f"""
        QListWidget {{
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 8px;
            color: {TEXT};
            font-family: {MONO};
            font-size: 13px;
            outline: none;
        }}
        QListWidget::item {{
            padding: 9px 14px;
            border-bottom: 1px solid {BORDER};
        }}
        QListWidget::item:selected {{
            background: #0D2035;
            color: {CYAN};
        }}
        QListWidget::item:hover {{
            background: #071525;
        }}
        {SCROLLBAR_CSS}
    """


def textedit_css():
    return f"""
        QTextEdit {{
            background: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 8px;
            color: {TEXT};
            font-family: {MONO};
            font-size: 12px;
            padding: 10px;
            selection-background-color: #0D2035;
        }}
        {SCROLLBAR_CSS}
    """


def input_css():
    return f"""
        QLineEdit {{
            background: {BG2};
            border: 1px solid {BORDER2};
            border-radius: 6px;
            color: {TEXT};
            font-family: {MONO};
            font-size: 13px;
            padding: 8px 12px;
        }}
        QLineEdit:focus {{
            border-color: {CYAN_DIM};
        }}
        QLineEdit::placeholder {{
            color: {TEXT_DIM};
        }}
    """


def combo_css():
    return f"""
        QComboBox {{
            background: {BG2};
            border: 1px solid {BORDER2};
            border-radius: 6px;
            color: {TEXT};
            font-family: {MONO};
            font-size: 12px;
            padding: 6px 12px;
        }}
        QComboBox:hover {{ border-color: {CYAN_DIM}; }}
        QComboBox::drop-down {{ border: none; width: 20px; }}
        QComboBox QAbstractItemView {{
            background: {PANEL};
            border: 1px solid {BORDER2};
            color: {TEXT};
            selection-background-color: #0D2035;
        }}
    """
