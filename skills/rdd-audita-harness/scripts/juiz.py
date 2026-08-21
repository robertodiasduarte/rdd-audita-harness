"""C3 — cliente do juiz (capacidade × propósito). stdlib apenas.

⛔⛔ LANDMINE CENTRAL: o texto entregue ao LLM passa OBRIGATORIAMENTE por
`neutralizar.para_llm()`. Se alguém mandar o byte cru, o modelo ingere o payload
invisível como instrução e o auditor vira vítima — a falha que esta arquitetura
inteira existe para evitar. A neutralização acontece AQUI DENTRO, não no caller,
justamente para que nenhum caller possa esquecer.

⚠️ Exceção consciente à regra "toda LLM via _shared/llm.ts" (CLAUDE.md): aquela
camada é TS/edge. Esta skill é Python e roda na máquina de quem instala — no
harness do aluno não existe `_shared`. Precedente: skills/dica-do-dia/scripts/gerar.py.
"""
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import neutralizar  # noqa: E402
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts"))

API_URL = "https://api.anthropic.com/v1/messages"
MODEL_PADRAO = os.environ.get("AUDITOR_C3_MODELO", "claude-sonnet-4-6")
ENV_PADRAO = os.path.expanduser("~/.config/rdd-eval.env")


class C3Indisponivel(Exception):
    """Sem chave, sem rede ou resposta inválida — a C3 é PULADA, nunca inventa verde."""


def carregar_chave(caminho=ENV_PADRAO):
    k = os.environ.get("ANTHROPIC_API_KEY")
    if k:
        return k
    if os.path.exists(caminho):
        with open(caminho, encoding="utf-8") as f:
            for linha in f:
                if linha.startswith("ANTHROPIC_API_KEY="):
                    return linha.split("=", 1)[1].strip().strip('"').strip("'")
    raise C3Indisponivel(
        f"ANTHROPIC_API_KEY ausente (env ou {caminho}) — C3 pulada")


def _prompts():
    import importlib.util
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "prompts", "juiz-v1.py")
    spec = importlib.util.spec_from_file_location("juiz_v1", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def julgar(inventario, texto_cru, modelo=None, timeout=90, chave=None):
    """Um julgamento por arquivo. Devolve dict do contrato do juiz.

    `texto_cru` entra CRU e é neutralizado aqui — ver landmine no topo.
    """
    modelo = modelo or MODEL_PADRAO
    chave = chave or carregar_chave()
    pr = _prompts()

    seguro = neutralizar.para_llm(texto_cru)          # ⛔ o passo que não pode faltar
    payload = {
        "model": modelo,
        "max_tokens": 1024,
        "system": pr.SYSTEM,
        "messages": [{"role": "user", "content": pr.montar_user(inventario, seguro)}],
    }
    req = urllib.request.Request(
        API_URL, data=json.dumps(payload).encode("utf-8"),
        headers={"content-type": "application/json", "x-api-key": chave,
                 "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise C3Indisponivel(f"HTTP {e.code}: {e.read()[:200].decode('utf-8','replace')}")
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise C3Indisponivel(f"rede: {e}")

    try:
        texto = "".join(b.get("text", "") for b in resp.get("content", []))
        ini, fim = texto.find("{"), texto.rfind("}")
        if ini == -1 or fim == -1:
            raise ValueError("sem JSON na resposta")
        return json.loads(texto[ini:fim + 1])
    except (ValueError, KeyError, json.JSONDecodeError) as e:
        raise C3Indisponivel(f"resposta não-parseável: {e}")


def achados_de(veredito, arquivo):
    """Converte o veredito do juiz em achados do formato do auditor."""
    out = []
    for a in (veredito.get("achados") or []):
        sev = str(a.get("severidade", "MEDIUM")).upper()
        if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            sev = "MEDIUM"
        det = a.get("detalhe", "")
        if a.get("porque_nao_bate"):
            det = f"{det} — {a['porque_nao_bate']}"
        out.append({
            "regra": "c3.capacidade_sem_proposito", "severidade": sev,
            "arquivo": arquivo, "linha": 0, "coluna": 1, "codepoint": "—",
            "detalhe": det, "taxonomia": ["LLM01", "LLM06"], "trecho": "",
        })
    return out
