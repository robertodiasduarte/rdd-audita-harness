"""C1 — neutralização. Nada é lido por LLM antes de passar por aqui.

⛔ LANDMINE CENTRAL: unicode invisível é instrução para o modelo e nada para o olho
humano. Se o auditor LLM ingere o byte cru, ele obedece o payload — o auditor vira
vítima. Por isso `para_llm()` é a ÚNICA porta de entrada do C3.
"""
import unicodedata

# Faixas invisíveis/direcionais. Cada uma é CRITICAL por si só: não há uso legítimo
# conhecido em skill/agent/command.
FAIXAS = [
    ("tags_block", 0xE0000, 0xE007F, "tags block (payload invisível para o modelo)"),
    ("zero_width", 0x200B, 0x200D, "zero-width"),
    ("zero_width", 0x2060, 0x2060, "word joiner"),
    ("zero_width", 0xFEFF, 0xFEFF, "BOM/zero-width no-break"),
    ("bidi", 0x202A, 0x202E, "bidi override (CVE-2021-42574)"),
    ("bidi", 0x2066, 0x2069, "bidi isolate (CVE-2021-42574)"),
]


def classificar(cp: int):
    """Devolve (familia, descricao) se o codepoint for invisível/bidi; senão None."""
    for familia, ini, fim, desc in FAIXAS:
        if ini <= cp <= fim:
            return familia, desc
    return None


def achados_unicode(texto: str, arquivo: str):
    """Todo caractere invisível/bidi, com linha:coluna e codepoint (AT-04)."""
    out = []
    for nl, linha in enumerate(texto.splitlines(), 1):
        for nc, ch in enumerate(linha, 1):
            hit = classificar(ord(ch))
            if hit:
                familia, desc = hit
                out.append({
                    "regra": f"unicode.{familia}",
                    "severidade": "CRITICAL",
                    "arquivo": arquivo,
                    "linha": nl,
                    "coluna": nc,
                    "codepoint": f"U+{ord(ch):04X}",
                    "detalhe": desc,
                })
    return out


def para_llm(texto: str) -> str:
    """Texto seguro para um LLM ler: NFKC + todo não-ASCII em hex visível (AT-01).

    Depois disto não resta nenhum caractere invisível — o que era payload vira
    literal `‹U+XXXX›`, visível e inerte.
    """
    norm = unicodedata.normalize("NFKC", texto)
    return "".join(c if ord(c) < 128 else f"‹U+{ord(c):04X}›" for c in norm)
