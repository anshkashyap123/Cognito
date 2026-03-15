#!/usr/bin/env python3
# cognito_main.py  –  COGNITO XDR v3.0
# Entry point: splash screen, dependency checks, cross-platform launch

import sys
import os
import time

# ── Ensure CWD is always the project root ─────────────────────────────────────
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# ── Dependency check ─────────────────────────────────────────────────────────

REQUIRED = [
    ("PyQt5",       "PyQt5"),
    ("numpy",       "numpy"),
    ("sklearn",     "scikit-learn"),
    ("matplotlib",  "matplotlib"),
    ("requests",    "requests"),
]

missing = []
for module, pkg in REQUIRED:
    try:
        __import__(module)
    except ImportError:
        missing.append(pkg)

if missing:
    print("\n[COGNITO] Missing required packages:")
    for pkg in missing:
        print(f"   pip install {pkg}")
    print("\nInstall all at once:")
    print("   pip install -r requirements.txt\n")
    sys.exit(1)

# ── Qt Application ────────────────────────────────────────────────────────────

from PyQt5.QtWidgets import QApplication, QSplashScreen, QLabel
from PyQt5.QtCore    import Qt, QTimer
from PyQt5.QtGui     import QPixmap, QPainter, QColor, QFont, QLinearGradient

from gui.cognito_dashboard import CognitoDashboard
from gui import theme as T


def make_splash() -> QSplashScreen:
    """Create a styled splash screen."""
    px = QPixmap(640, 360)
    px.fill(QColor(T.BG))

    p = QPainter(px)
    p.setRenderHint(QPainter.Antialiasing)

    # Background gradient
    grad = QLinearGradient(0, 0, 640, 360)
    grad.setColorAt(0, QColor("#010B14"))
    grad.setColorAt(1, QColor("#030F1C"))
    p.fillRect(0, 0, 640, 360, grad)

    # Border
    p.setPen(QColor(T.BORDER2))
    p.drawRect(0, 0, 639, 359)
    p.setPen(QColor(T.CYAN + "44"))
    p.drawRect(4, 4, 631, 351)

    # Title
    p.setPen(QColor(T.CYAN))
    font = QFont("Consolas", 52, QFont.Bold)
    p.setFont(font)
    p.drawText(0, 60, 640, 100, Qt.AlignCenter, "COGNITO")

    # Subtitle
    p.setPen(QColor(T.TEXT_DIM))
    font2 = QFont("Consolas", 12)
    p.setFont(font2)
    p.drawText(0, 150, 640, 30, Qt.AlignCenter, "MILITARY-GRADE EXTENDED DETECTION & RESPONSE")
    p.drawText(0, 180, 640, 25, Qt.AlignCenter, "v3.0  ·  ALPHA BUILD")

    # Corner decorations
    c = QColor(T.CYAN + "50")
    p.setPen(c)
    p.drawLine(20, 20, 80, 20)
    p.drawLine(20, 20, 20, 80)
    p.drawLine(560, 20, 620, 20)
    p.drawLine(620, 20, 620, 80)
    p.drawLine(20, 340, 80, 340)
    p.drawLine(20, 280, 20, 340)
    p.drawLine(560, 340, 620, 340)
    p.drawLine(620, 280, 620, 340)

    # Loading text
    p.setPen(QColor(T.CYAN))
    font3 = QFont("Consolas", 11)
    p.setFont(font3)
    p.drawText(0, 310, 640, 25, Qt.AlignCenter, "INITIALIZING THREAT ENGINE...")

    p.end()
    splash = QSplashScreen(px, Qt.WindowStaysOnTopHint)
    return splash


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("COGNITO XDR")
    app.setApplicationVersion("3.0")
    app.setStyle("Fusion")

    # ── Splash ─────────────────────────────────────────────────────────────
    splash = make_splash()
    splash.show()
    app.processEvents()

    # ── Apply global Fusion dark palette ───────────────────────────────────
    from PyQt5.QtGui import QPalette
    palette = QPalette()
    palette.setColor(QPalette.Window,          QColor(T.BG))
    palette.setColor(QPalette.WindowText,      QColor(T.TEXT))
    palette.setColor(QPalette.Base,            QColor(T.BG2))
    palette.setColor(QPalette.AlternateBase,   QColor(T.PANEL))
    palette.setColor(QPalette.ToolTipBase,     QColor(T.PANEL))
    palette.setColor(QPalette.ToolTipText,     QColor(T.TEXT))
    palette.setColor(QPalette.Text,            QColor(T.TEXT))
    palette.setColor(QPalette.Button,          QColor(T.BG2))
    palette.setColor(QPalette.ButtonText,      QColor(T.TEXT))
    palette.setColor(QPalette.BrightText,      QColor(T.TEXT_BRIGHT))
    palette.setColor(QPalette.Link,            QColor(T.CYAN))
    palette.setColor(QPalette.Highlight,       QColor("#0D2035"))
    palette.setColor(QPalette.HighlightedText, QColor(T.CYAN))
    app.setPalette(palette)

    # ── Platform check ─────────────────────────────────────────────────────
    import platform
    system = platform.system()
    if system not in ("Windows", "Linux", "Darwin"):
        print(f"[COGNITO] Warning: unsupported OS '{system}'")

    # ── Short init delay for splash ────────────────────────────────────────
    time.sleep(1.2)

    # ── Main window ────────────────────────────────────────────────────────
    window = CognitoDashboard()
    window.show()
    splash.finish(window)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
