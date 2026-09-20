---
name: rdd-audita-harness
description: |
  Audita skills, agentes, comandos, hooks, settings e MCP servers antes de você
  instalar ou confiar — procurando easter eggs, código malicioso, backdoors e
  exfiltração. Alvo = o que o AGENTE executa (diferente do /security:audit, que
  audita a aplicação). Invocar quando alguém disser "audita essa skill", "é seguro
  instalar esse plugin", "confere esse agente antes de usar", ou colar um repo de
  skills pedindo verificação. READ-ONLY: nunca altera o material auditado.
license: MIT
metadata:
  author: Roberto Dias Duarte
---

# Audite o que a sua IA executa

Você instala uma skill e ela passa a rodar com as suas permissões. A Snyk varreu
3.984 skills em fev/2026: **36,8% com ≥1 falha, 13,4% críticas, 76 com payload
malicioso confirmado** — e **91% das maliciosas combinam prompt injection com
malware tradicional**.

Duas propriedades tornam a revisão a olho insuficiente:

1. **O payload dominante é linguagem natural, não código.** Scanner só de código
   erra a maior parte do problema.
2. **Unicode invisível derrota o olho humano por construção.** Tags block,
   zero-width e bidi mudam o que o modelo lê sem mudar o que você vê.

## Como rodar

```bash
# harness do Claude Code
python3 scripts/auditar.py \
    .claude/skills .claude/agents .claude/commands \
    ~/.claude/hooks ~/.claude/settings.json .mcp.json

# harness do Codex — config.toml, rules, hooks e as 3 pastas de skills
python3 scripts/auditar.py \
    ~/.codex/config.toml ~/.codex/rules ~/.codex/hooks.json \
    ~/.codex/skills ~/.agents/skills ~/.codex/AGENTS.md

# no projeto, os dois de uma vez
python3 scripts/auditar.py .claude .codex .agents/skills AGENTS.md .mcp.json

# antes de instalar algo de terceiro
python3 scripts/auditar.py ~/Downloads/skill-nova/

# rug pull: grave o baseline hoje, compare a cada atualização
python3 scripts/auditar.py .claude/skills \
    --baseline .claude/.auditoria-baseline.json --gravar-baseline

# C3 — capacidade × propósito (pega payload em LINGUAGEM NATURAL)
python3 scripts/auditar.py ~/Downloads/skill-nova/ --dossie
```

### O que muda no Codex

O harness do Codex guarda as mesmas capacidades em arquivos diferentes, e o auditor
os alcança por **nome**, não por extensão:

| Arquivo | O que o auditor procura |
|---|---|
| `config.toml` (do usuário e do projeto) | servidor MCP que roda binário local, credencial inline em `env`, MCP sem TLS, `sandbox_mode = "danger-full-access"`, `approval_policy = "never"`, projetos marcados como confiáveis, `notify`, plugins ativos |
| `rules/*.rules` | **credencial em texto puro dentro de `prefix_rule`** — "sempre permitir" grava o comando inteiro, então um `curl` com token no cabeçalho vira segredo persistido |
| `hooks.json` | comando que roda sozinho, sem confirmação, a cada evento do ciclo |
| `AGENTS.md` / `AGENTS.override.md` | instrução maliciosa em linguagem natural; e aviso quando o arquivo passa de 28 KiB, porque o Codex soma esses arquivos até 32 KiB e **para de incluir em silêncio** |

⚠️ **Ler `config.toml` exige TOML.** No Python 3.11+ é nativo; antes disso, instale
`pip3 install tomli`. Sem nenhum dos dois o auditor **declara que não leu** aquele arquivo
e sai com erro — nunca dá verde sobre um arquivo que não abriu.

### A C3 tem dois caminhos — prefira o primeiro

**`--dossie` (recomendado).** Esta skill já roda dentro de um agente: **você é o LLM**.
O script emite o material neutralizado com as instruções de julgamento, e quem julga é
o agente que carregou a skill. **Custo zero, sem chave de API, sem segunda cobrança** —
você já está pagando pela sessão. É o mesmo padrão das skills irmãs: o script faz a
parte determinística, o agente faz o juízo.

**`--c3` (para automação).** Chama a API diretamente, útil quando o auditor roda em CI
ou em lote, sem agente na frente. Custa dinheiro por arquivo e o veredito pode variar
entre rodadas. Chave: `ANTHROPIC_API_KEY` (env ou `~/.config/rdd-eval.env`); modelo via
`AUDITOR_C3_MODELO`. Se falhar (sem chave/rede), o relatório **diz** que o resultado
está incompleto — nunca finge verde.

Sem nenhum dos dois, o auditor é 100% determinístico: mesma entrada, mesma saída, e
cego para o payload em linguagem natural.

Para provar que o caminho `--c3` funciona na sua máquina (chamada real, 3 runs):

```bash
python3 scripts/eval_c3.py
```

Exit **0** = nada HIGH/CRITICAL · **1** = achado HIGH/CRITICAL (estilo grep: "achou"
é exit≠0, não é erro) · **2** = erro de uso.

## As 4 camadas

| Camada | O que faz | Por quê |
|---|---|---|
| **C1** determinística | NFKC + dump hex do não-ASCII, depois regras | Nada é lido por LLM antes de ser neutralizado |
| **C2** capacidades | Domínios, shell, arquivos, env, MCP, allowed-tools, config | Capacidade sensível é INFO — o julgamento é da C3 |
| **C3** LLM-as-judge | "esta capacidade serve ao propósito DECLARADO?" | Pega o payload em linguagem natural |
| **C4** diff/baseline | Compara com baseline assinado por SHA-256 | Única defesa contra **rug pull** |

## Como ler o resultado

O veredito é do conjunto, não da regra isolada:

- **Limpa** — zero HIGH/CRITICAL e toda capacidade explicada pelo propósito declarado.
- **Suspeita** — capacidade que o propósito não explica. Não é condenação: é a
  pergunta que você leva ao autor antes de instalar.
- **Comprometida** — unicode invisível, instrução para ocultar ação do usuário, ou
  exfiltração de segredo. Não instale.

⛔ **Capacidade sensível sozinha não condena.** Uma skill que publica no banco
legitimamente usa credencial de serviço e rede. O teste é *capacidade × propósito* —
uma regra que reprovasse todas elas estaria errada.

⚠️ **Scan limpo NÃO prova que o material é benigno.** Este auditor cobre padrões
conhecidos e coerência capacidade×propósito. Ausência de achado é ausência de
**evidência**, não prova de segurança. O relatório diz isso sempre — de propósito.

## Fora de escopo

- Não corrige nada: **reporta**. Aplicar `deny` em `settings.json` é decisão sua.
- Não executa o material auditado (sem sandbox, sem análise dinâmica).

---

Skill de Roberto Dias Duarte — https://github.com/robertodiasduarte/rdd-audita-harness
