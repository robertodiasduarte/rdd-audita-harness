#!/usr/bin/env python3
"""Auditor de harness — skills, agents, commands, hooks, settings, MCP.

Alvo: o que o AGENTE executa (≠ /security:audit, que audita a aplicação RDD).

Uso:
  python3 auditar.py <caminho> [<caminho>...] [--json] [--baseline FILE] [--gravar-baseline]

Exit: 0 nada HIGH/CRITICAL · 1 achado HIGH/CRITICAL · 2 erro de uso.
(estilo grep: "achou" é exit≠0, não é crash)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import capacidades  # noqa: E402
import config  # noqa: E402
import neutralizar  # noqa: E402
import regras  # noqa: E402

EXTS = {".md", ".py", ".sh", ".ts", ".js", ".json", ".yaml", ".yml"}
IGNORAR = {".git", "node_modules", "__pycache__", ".venv"}
ORDEM = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

RESSALVA = (
    "Scan limpo NAO prova que o material e benigno: este auditor cobre padroes "
    "conhecidos e capacidade x proposito declarado. Ausencia de achado e ausencia "
    "de EVIDENCIA, nao prova de seguranca."
)


def coletar(alvos):
    for alvo in alvos:
        if os.path.isfile(alvo):
            yield alvo
            continue
        for raiz, dirs, arqs in os.walk(alvo):
            dirs[:] = [d for d in dirs if d not in IGNORAR]
            for a in sorted(arqs):
                if os.path.splitext(a)[1] in EXTS:
                    yield os.path.join(raiz, a)


def auditar(alvos, baseline=None, gravar=False):
    achados, inventario = [], []
    base_abs = os.path.abspath(baseline) if baseline else None
    for caminho in coletar(alvos):
        # o arquivo de baseline e artefato do proprio auditor, nao alvo
        if base_abs and os.path.abspath(caminho) == base_abs:
            continue
        try:
            texto = open(caminho, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        ext = os.path.splitext(caminho)[1]
        # C1 — unicode primeiro: nada segue adiante sem neutralização
        achados += neutralizar.achados_unicode(texto, caminho)
        achados += regras.aplicar(texto, caminho, ext)
        # C2b — postura de config (risco que regex de conteúdo não pega)
        base = os.path.basename(caminho)
        if base in ("settings.json", "settings.local.json"):
            achados += config.auditar_settings(caminho)
        elif base == ".mcp.json":
            achados += config.auditar_mcp(caminho)
        # C2
        inventario.append(capacidades.inventariar(texto, caminho))

    # C4
    diff = None
    if baseline:
        diff = capacidades.diff_baseline(inventario, baseline)
        if diff:
            achados += diff
        if gravar:
            capacidades.gravar_baseline(inventario, baseline)

    achados.sort(key=lambda a: (ORDEM.get(a["severidade"], 9), a["arquivo"], a["linha"]))
    return achados, inventario, diff


def relatorio(achados, inventario, diff, baseline):
    por_sev = {}
    for a in achados:
        por_sev[a["severidade"]] = por_sev.get(a["severidade"], 0) + 1

    print("=" * 72)
    print("AUDITORIA DE HARNESS — o que o seu agente executa")
    print("=" * 72)
    print(f"Arquivos auditados : {len(inventario)}")
    print(f"Achados            : {len(achados)}  " +
          " ".join(f"{k}={v}" for k, v in sorted(por_sev.items(), key=lambda x: ORDEM.get(x[0], 9))))
    if baseline and diff is None:
        print("Baseline (C4)      : ausente — 1a rodada, nada a comparar (rug pull so detecta da 2a em diante)")
    elif baseline:
        print(f"Baseline (C4)      : comparado ({len(diff)} mudancas)")
    print()

    if achados:
        print("── ACHADOS ──")
        for a in achados:
            loc = f"{a['arquivo']}:{a['linha']}" + (f":{a['coluna']}" if a["linha"] else "")
            print(f"[{a['severidade']:8}] {a['regra']:32} {loc}")
            print(f"             {a['detalhe']}")
            if a.get("codepoint", "—") != "—":
                print(f"             codepoint: {a['codepoint']}")
            if a.get("trecho"):
                # trecho tambem neutralizado: relatorio nunca imprime byte invisivel cru
                print(f"             trecho: {neutralizar.para_llm(a['trecho'])}")
            if a.get("taxonomia"):
                print(f"             taxonomia: {', '.join(a['taxonomia'])}")
        print()

    sensiveis = [i for i in inventario if i["capacidades"]]
    print(f"── INVENTARIO DE CAPACIDADES (C2) — {len(sensiveis)} arquivo(s) com capacidade sensivel ──")
    print("   (INFO: capacidade coerente com o proposito declarado NAO e achado)")
    for i in sensiveis[:15]:
        print(f"   {i['arquivo']}: {', '.join(i['capacidades'])}")
    if len(sensiveis) > 15:
        print(f"   … +{len(sensiveis)-15}")
    print()
    print("⚠️  " + RESSALVA)
    print("=" * 72)


def main():
    ap = argparse.ArgumentParser(description="Audita skills/agents/commands/hooks.")
    ap.add_argument("alvos", nargs="+")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--baseline")
    ap.add_argument("--gravar-baseline", action="store_true")
    args = ap.parse_args()

    for a in args.alvos:
        if not os.path.exists(a):
            print(f"erro: caminho inexistente: {a}", file=sys.stderr)
            return 2

    achados, inventario, diff = auditar(args.alvos, args.baseline, args.gravar_baseline)

    if args.json:
        print(json.dumps({"achados": achados, "inventario": inventario,
                          "ressalva": RESSALVA}, indent=2, ensure_ascii=False))
    else:
        relatorio(achados, inventario, diff, args.baseline)

    grave = [a for a in achados if a["severidade"] in ("CRITICAL", "HIGH")]
    return 1 if grave else 0


if __name__ == "__main__":
    sys.exit(main())
