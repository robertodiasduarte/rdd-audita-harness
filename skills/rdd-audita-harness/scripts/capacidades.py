"""C2 — inventário de capacidades · C4 — baseline assinado e diff (rug pull).

⛔ AT-06: capacidade sensível NÃO é achado. As 6 skills que usam service_role são
legítimas. O teste é capacidade × propósito (C3), não capacidade isolada — aqui só
se INVENTARIA, sempre em severidade INFO.
"""
import hashlib
import json
import os
import re

PADROES = {
    "rede": r"\b(curl|wget|fetch\(|requests\.|urllib|http\.client|axios)\b",
    "shell": r"\b(subprocess|os\.system|child_process|Bash\(|execSync)\b",
    "escrita_fs": r"\b(open\([^)]*['\"][wa]|Write\(|writeFile|>>?\s*/)",
    "segredo": r"(service_role|SERVICE_ROLE|API_KEY|_TOKEN|_SECRET|password|senha)",
    "env": r"(os\.environ|process\.env|Deno\.env)",
    "mcp": r"\bmcp__\w+",
}
_RX = {k: re.compile(v) for k, v in PADROES.items()}

DOMINIO_RX = re.compile(r"https?://([a-zA-Z0-9.\-]+)")


def frontmatter(texto: str) -> dict:
    """Frontmatter YAML raso (name/description/allowed-tools/model)."""
    if not texto.startswith("---"):
        return {}
    fim = texto.find("\n---", 3)
    if fim == -1:
        return {}
    fm, chave, bloco = {}, None, []
    for linha in texto[3:fim].splitlines():
        # continuação de escalar de bloco (description: | / >) — indentada
        if chave and (linha.startswith((" ", "\t")) or not linha.strip()):
            bloco.append(linha.strip())
            continue
        if chave:
            fm[chave] = " ".join(x for x in bloco if x).strip()
            chave, bloco = None, []
        if ":" in linha and not linha.startswith((" ", "\t")):
            k, _, v = linha.partition(":")
            v = v.strip()
            if v in ("|", ">", "|-", ">-", "|+", ">+"):
                chave = k.strip()          # valor real vem nas linhas indentadas
            else:
                fm[k.strip()] = v
    if chave:
        fm[chave] = " ".join(x for x in bloco if x).strip()
    return fm


def inventariar(texto: str, arquivo: str) -> dict:
    caps = sorted(k for k, rx in _RX.items() if rx.search(texto))
    dominios = sorted(set(DOMINIO_RX.findall(texto)))
    fm = frontmatter(texto)
    return {
        "arquivo": arquivo,
        "sha256": hashlib.sha256(texto.encode("utf-8")).hexdigest(),
        "capacidades": caps,
        "dominios": dominios,
        "proposito_declarado": (fm.get("description") or fm.get("name") or "")[:300],
        "allowed_tools": fm.get("allowed-tools", ""),
    }


# ── C4 ────────────────────────────────────────────────────────────────────────

def gravar_baseline(inventario, caminho):
    dados = {i["arquivo"]: {"sha256": i["sha256"], "capacidades": i["capacidades"],
                            "dominios": i["dominios"]} for i in inventario}
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados, f, indent=2, sort_keys=True, ensure_ascii=False)
    return len(dados)


def diff_baseline(inventario, caminho):
    """Capacidade/domínio NOVO desde o baseline = achado (rug pull, MCP03).

    Rodada 1 não tem baseline: devolve [] e o relatório diz 'sem baseline anterior'.
    Isso é ausência de dado, não ausência de risco (AT-07).
    """
    if not os.path.exists(caminho):
        return None
    with open(caminho, encoding="utf-8") as f:
        base = json.load(f)
    achados = []
    for item in inventario:
        antes = base.get(item["arquivo"])
        if antes is None:
            achados.append({
                "regra": "rugpull.arquivo_novo", "severidade": "MEDIUM",
                "arquivo": item["arquivo"], "linha": 0, "coluna": 1, "codepoint": "—",
                "detalhe": "arquivo não existia no baseline anterior",
                "taxonomia": ["MCP03"], "trecho": "",
            })
            continue
        # Conteúdo mudou sem mudar capacidade: um knob de postura (ex.:
        # skipDangerousModePermissionPrompt) liga sem adicionar rede/shell/segredo.
        # Sem isto, C4 fica cego para mudança de CONFIG — só via capacidade nova.
        if antes.get("sha256") and antes["sha256"] != item["sha256"]:
            achados.append({
                "regra": "rugpull.conteudo_alterado", "severidade": "MEDIUM",
                "arquivo": item["arquivo"], "linha": 0, "coluna": 1, "codepoint": "—",
                "detalhe": (f"conteúdo mudou desde o baseline "
                            f"(sha {antes['sha256'][:12]}… → {item['sha256'][:12]}…)"),
                "taxonomia": ["MCP03"], "trecho": "",
            })
        novas = set(item["capacidades"]) - set(antes.get("capacidades", []))
        novos_dom = set(item["dominios"]) - set(antes.get("dominios", []))
        if novas:
            achados.append({
                "regra": "rugpull.capacidade_nova", "severidade": "HIGH",
                "arquivo": item["arquivo"], "linha": 0, "coluna": 1, "codepoint": "—",
                "detalhe": f"capacidade nova desde o baseline: {sorted(novas)}",
                "taxonomia": ["MCP03", "LLM03"], "trecho": "",
            })
        if novos_dom:
            achados.append({
                "regra": "rugpull.dominio_novo", "severidade": "HIGH",
                "arquivo": item["arquivo"], "linha": 0, "coluna": 1, "codepoint": "—",
                "detalhe": f"domínio novo desde o baseline: {sorted(novos_dom)}",
                "taxonomia": ["MCP03", "LLM02"], "trecho": "",
            })
    return achados
