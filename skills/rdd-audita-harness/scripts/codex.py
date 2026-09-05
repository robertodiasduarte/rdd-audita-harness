"""C2b — postura de configuracao do harness do CODEX.

Espelha config.py (que cobre o harness do Claude Code: settings.json + .mcp.json).
Alvos, conforme a documentacao oficial do Codex:

  ~/.codex/config.toml  ·  <repo>/.codex/config.toml   (config; projeto so se trusted)
  ~/.codex/hooks.json   ·  <repo>/.codex/hooks.json    (hooks: rodam sem prompt)
  ~/.codex/rules/*.rules · <repo>/.codex/rules/*.rules (execpolicy; "sempre permitir" grava aqui)
  AGENTS.md / AGENTS.override.md                       (instrucoes lidas em toda sessao)

⛔ NAO le TOML "na marra": tomllib (3.11+) -> tomli -> DEGRADA declarando que NAO LEU.
   Verde silencioso sobre arquivo nao lido e a falha que este modulo existe para evitar.

⛔ A skill REPORTA; nao corrige configuracao alheia.
"""
import os

try:
    import tomllib as _toml           # Python >= 3.11
except ModuleNotFoundError:
    try:
        import tomli as _toml         # backport opcional
    except ModuleNotFoundError:
        _toml = None

# Permite ao gate exercitar o ramo degradado sem desinstalar nada.
if os.environ.get("AUDITOR_SEM_TOML"):
    _toml = None

TOML_DISPONIVEL = _toml is not None


def _achado(regra, sev, arquivo, detalhe, taxonomia, linha=0, trecho=""):
    return {"regra": regra, "severidade": sev, "arquivo": arquivo, "linha": linha,
            "coluna": 1, "codepoint": "—", "detalhe": detalhe,
            "taxonomia": taxonomia, "trecho": trecho}


def auditar_config_toml(caminho):
    """config.toml do Codex: MCP, sandbox, approval, trust, notify, hooks inline, plugins."""
    if not os.path.exists(caminho):
        return []

    if _toml is None:
        # HIGH (nao MEDIUM) de proposito: garante exit != 0 pelo caminho normal do auditar.py.
        return [_achado(
            "codex.config_nao_lido", "HIGH", caminho,
            "config.toml NAO LIDO: sem tomllib (Python <3.11) e sem tomli. "
            "Instale com 'pip3 install tomli' ou use Python 3.11+. "
            "O restante do harness foi auditado; ESTE arquivo nao — resultado incompleto.",
            ["LLM06"])]

    try:
        with open(caminho, "rb") as f:
            d = _toml.load(f)
    except Exception:
        return [_achado("codex.config_ilegivel", "MEDIUM", caminho,
                        "config.toml nao pode ser lido/parseado", ["LLM06"])]

    out = []

    for nome, cfg in (d.get("mcp_servers") or {}).items():
        if not isinstance(cfg, dict):
            continue
        if cfg.get("command"):
            args = " ".join(str(a) for a in (cfg.get("args") or []))[:60]
            out.append(_achado(
                "codex.mcp_local", "MEDIUM", caminho,
                f"server '{nome}' executa binario local: {cfg.get('command')} {args} "
                "— codigo de terceiro rodando na sua maquina", ["MCP03", "MCP09"]))
        env = cfg.get("env") or {}
        if isinstance(env, dict) and env:
            out.append(_achado(
                "codex.mcp_env_inline", "MEDIUM", caminho,
                f"server '{nome}' recebe {len(env)} variavel(is) de ambiente inline "
                f"({', '.join(sorted(env)[:4])}) — valor de credencial no arquivo de config",
                ["LLM02", "MCP09"]))
        url = str(cfg.get("url") or "")
        if url.startswith("http://"):
            out.append(_achado("codex.mcp_sem_tls", "HIGH", caminho,
                               f"server '{nome}' em HTTP sem TLS: {url}", ["MCP09"]))
        elif url:
            out.append(_achado("codex.mcp_remoto", "INFO", caminho,
                               f"server '{nome}' → {url[:70]}", ["MCP09"]))

    sandbox = str(d.get("sandbox_mode") or "")
    if sandbox == "danger-full-access":
        out.append(_achado(
            "codex.sandbox_desligado", "HIGH", caminho,
            "sandbox_mode='danger-full-access': o agente le e escreve fora do workspace "
            "e alcanca a rede sem restricao", ["LLM06"]))

    aprov = d.get("approval_policy")
    if isinstance(aprov, str) and aprov == "never":
        out.append(_achado(
            "codex.aprovacao_nunca", "HIGH", caminho,
            "approval_policy='never': nenhum comando pede confirmacao", ["LLM06"]))

    confiaveis = [p for p, cfg in (d.get("projects") or {}).items()
                  if isinstance(cfg, dict) and cfg.get("trust_level") == "trusted"]
    if confiaveis:
        out.append(_achado(
            "codex.projetos_confiaveis", "INFO", caminho,
            f"{len(confiaveis)} projeto(s) marcados 'trusted': cada um carrega .codex/config.toml, "
            "hooks e rules PROPRIOS — auditar cada repo, nao so este arquivo", ["LLM06"]))

    if d.get("notify"):
        alvo = d["notify"][0] if isinstance(d["notify"], list) and d["notify"] else d["notify"]
        out.append(_achado("codex.notify_declarado", "INFO", caminho,
                           f"notify executa a cada evento: {str(alvo)[:70]}", ["LLM06"]))

    hooks_inline = d.get("hooks") or {}
    if hooks_inline:
        out.append(_achado(
            "codex.hook_declarado", "INFO", caminho,
            f"{len(hooks_inline)} evento(s) de hook inline no config.toml: rodam sem prompt",
            ["LLM06"]))

    plugins = d.get("plugins") or {}
    ativos = [n for n, cfg in plugins.items() if isinstance(cfg, dict) and cfg.get("enabled")]
    if ativos:
        out.append(_achado(
            "codex.plugins_ativos", "INFO", caminho,
            f"{len(ativos)} plugin(s) habilitados: cada um pode trazer skills, MCP e hooks "
            "— auditar a origem (marketplace)", ["MCP03"]))

    return out


def auditar_hooks_json(caminho):
    """hooks.json do Codex: comando que roda sozinho, sem prompt."""
    if not os.path.exists(caminho):
        return []
    import json
    try:
        with open(caminho, encoding="utf-8") as f:
            d = json.load(f)
    except (json.JSONDecodeError, OSError):
        return [_achado("codex.hooks_ilegivel", "MEDIUM", caminho,
                        "hooks.json nao pode ser lido/parseado", ["LLM06"])]

    out = []
    eventos = d.get("hooks") or {}
    total = 0
    for evento, grupos in eventos.items():
        if not isinstance(grupos, list):
            continue
        for grupo in grupos:
            for h in (grupo.get("hooks") or []) if isinstance(grupo, dict) else []:
                total += 1
                cmd = str(h.get("command") or "")
                if cmd:
                    out.append(_achado(
                        "codex.hook_declarado", "INFO", caminho,
                        f"hook em {evento} roda sem prompt: {cmd[:70]}", ["LLM06"]))
    if total:
        out.append(_achado(
            "codex.hooks_total", "INFO", caminho,
            f"{total} hook(s) em {len(eventos)} evento(s) — auditar cada script alvo",
            ["LLM06"]))
    return out


def auditar_agents_md(caminho):
    """AGENTS.md: instrucao lida em TODA sessao. Cap de 32 KiB corta em silencio."""
    if not os.path.exists(caminho):
        return []
    try:
        tamanho = os.path.getsize(caminho)
    except OSError:
        return []
    out = []
    if tamanho > 28 * 1024:
        out.append(_achado(
            "codex.agents_md_grande", "INFO", caminho,
            f"{tamanho} bytes: o Codex soma os AGENTS.md ate 32 KiB "
            "(project_doc_max_bytes) e PARA de adicionar arquivos em silencio — "
            "instrucao de subpasta pode nunca chegar ao modelo", ["LLM01"]))
    return out


def eh_alvo_codex(caminho):
    """Basename/sufixo que o auditar.py roteia para este modulo."""
    base = os.path.basename(caminho)
    if base == "config.toml" or base == "hooks.json" or base.endswith(".rules"):
        return True
    return base in ("AGENTS.md", "AGENTS.override.md")


def auditar(caminho):
    """Despacho por basename. `.rules` cai nas regras de texto (regras.py), nao aqui."""
    base = os.path.basename(caminho)
    if base == "config.toml":
        return auditar_config_toml(caminho)
    if base == "hooks.json":
        return auditar_hooks_json(caminho)
    if base in ("AGENTS.md", "AGENTS.override.md"):
        return auditar_agents_md(caminho)
    return []
