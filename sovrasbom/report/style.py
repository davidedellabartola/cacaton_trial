"""Stile grafico della presentazione: colori, font, dimensioni.

Tutto in un solo file: per adattare la presentazione all'identita' visiva
dell'ente (o dell'azienda che ha proposto la sfida) basta cambiare questi valori.
"""

from pptx.dml.color import RGBColor
from pptx.util import Inches, Pt

SLIDE_W = Inches(13.333)
SLIDE_H = Inches(7.5)

TITLE_FONT = "Cambria"
BODY_FONT = "Calibri"

INK = RGBColor(0x13, 0x23, 0x3A)        # colore dominante: titoli, slide scure
TEXT = RGBColor(0x1F, 0x29, 0x37)
MUTED = RGBColor(0x5B, 0x65, 0x73)
LIGHT = RGBColor(0xC9, 0xD3, 0xDF)
TINT = RGBColor(0xEE, 0xF2, 0xF6)        # sfondo delle "card"
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
TEAL = RGBColor(0x0F, 0x76, 0x6E)        # esito positivo / accento principale
AMBER = RGBColor(0xC2, 0x6A, 0x05)       # attenzione
RED = RGBColor(0xB4, 0x23, 0x18)         # critico
GRID = RGBColor(0xDD, 0xE3, 0xEA)

SEVERITY_COLORS = {
    "Critical": RGBColor(0x8E, 0x16, 0x10),
    "High": RGBColor(0xC8, 0x3A, 0x1E),
    "Medium": RGBColor(0xD9, 0x8E, 0x04),
    "Low": RGBColor(0x5E, 0x8C, 0xA6),
    "Negligible": RGBColor(0x9A, 0xA5, 0xB1),
    "Unknown": RGBColor(0xB8, 0xC0, 0xC9),
}

LICENSE_COLORS = {
    "Permissiva": RGBColor(0x0F, 0x76, 0x6E),
    "Copyleft debole": RGBColor(0x3F, 0x9C, 0x92),
    "Copyleft forte": RGBColor(0x7F, 0xBF, 0xB6),
    "Copyleft di rete": RGBColor(0x2B, 0x4C, 0x7E),
    "Proprietaria / source-available": RGBColor(0xC8, 0x3A, 0x1E),
    "Non riconosciuta": RGBColor(0xD9, 0x8E, 0x04),
    "Assente": RGBColor(0xB8, 0xC0, 0xC9),
}

PRIORITY_COLORS = {1: RED, 2: AMBER, 3: TEAL}
PRIORITY_LABEL = {1: "Subito", 2: "A breve", 3: "Da pianificare"}

TITLE_SIZE = Pt(32)
BODY_SIZE = Pt(15)
SMALL_SIZE = Pt(12)
CAPTION_SIZE = Pt(10)


def level_color(score: int):
    if score < 0:
        return MUTED
    if score >= 75:
        return TEAL
    if score >= 50:
        return AMBER
    return RED
