"""C2b — postura de configuração (settings.json, .mcp.json).

⛔ Risco que NENHUM regex de conteúdo pega: a config pode estar sintaticamente
perfeita e ainda assim conceder tudo. Medido no harness em 21/08/2026:
2.232 regras allow e ZERO deny — contramedida citada pela Reversec é um
`deny` explícito, que sobrepõe config maliciosa.

⛔ A skill REPORTA a lacuna; não a corrige sozinha (fora de escopo do DEFINE:
aplicar `deny` exige decisão explícita do Roberto).
"""
import json
import os


def _achado(regra, sev, arquivo, detalhe, taxonomia):
    return {"regra": regra, "severidade": sev, "arquivo": arquivo, "linha": 0,
            "coluna": 1, "codepoint": "—", "detalhe": detalhe,
            "taxonomia": taxonomia, "trecho": ""}


def auditar_settings(caminho):
    """Postura de permissões + hooks declarados."""
    if not os.path.exists(caminho):
        return []
    try:
        with open(caminho, encoding="utf-8") as f:
            d = json.load(f)
    except (json.JSONDecodeError, OSError):
        return [_achado("config.ilegivel", "MEDIUM", caminho,
                        "settings.json não pôde ser lido/parseado", ["LLM06"])]

    out = []
    p = d.get("permissions") or {}
    n_allow, n_deny = len(p.get("allow", [])), len(p.get("deny", []))

    if n_allow and not n_deny:
        out.append(_achado(
            "config.allow_sem_deny", "MEDIUM", caminho,
            f"{n_allow} regras allow e ZERO deny: nada sobrepõe uma config maliciosa. "
            "Contramedida: deny explícito (ex.: Bash(*)) — decisão humana, não automática.",
            ["LLM06"]))

    for regra in p.get("allow", []):
        if isinstance(regra, str) and regra.replace(" ", "") in ("Bash(*)", "Bash(*:*)"):
            out.append(_achado("config.allow_bash_curinga", "CRITICAL", caminho,
                               f"allow concede Bash irrestrito: {regra}", ["LLM06"]))

    if d.get("skipDangerousModePermissionPrompt"):
        out.append(_achado(
            "config.pula_prompt_perigoso", "HIGH", caminho,
            "skipDangerousModePermissionPrompt=true: suprime a confirmação do modo perigoso",
            ["LLM06"]))

    # hooks executam SOZINHOS, sem prompt — inventariar sempre
    hooks = d.get("hooks") or {}
    if hooks:
        n = sum(len(v) if isinstance(v, list) else 1 for v in hooks.values())
        out.append(_achado("config.hooks_declarados", "INFO", caminho,
                           f"{n} hook(s) em {len(hooks)} evento(s): executam sem prompt — auditar o script alvo",
                           ["LLM06"]))
    return out


def auditar_mcp(caminho):
    """MCP: server com `command` executa binário local (MCP03/MCP09)."""
    if not os.path.exists(caminho):
        return []
    try:
        with open(caminho, encoding="utf-8") as f:
            d = json.load(f)
    except (json.JSONDecodeError, OSError):
        return []

    out = []
    for nome, cfg in (d.get("mcpServers") or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("command"):
            out.append(_achado(
                "mcp.servidor_local", "MEDIUM", caminho,
                f"server '{nome}' executa binário local: {cfg.get('command')} "
                f"{' '.join(cfg.get('args', []))[:60]} — código de terceiro rodando na sua máquina",
                ["MCP03", "MCP09"]))
        url = cfg.get("url", "")
        if url.startswith("http://"):
            out.append(_achado("mcp.sem_tls", "HIGH", caminho,
                               f"server '{nome}' em HTTP sem TLS: {url}", ["MCP09"]))
        elif url:
            out.append(_achado("mcp.servidor_remoto", "INFO", caminho,
                               f"server '{nome}' → {url[:70]}", ["MCP09"]))
    return out
