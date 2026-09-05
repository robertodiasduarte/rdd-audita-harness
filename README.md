# rdd-audita-harness

Skill que audita **o que a sua IA executa** — skills, agentes, comandos, hooks e servidores
MCP — procurando easter eggs, código malicioso, backdoors e exfiltração, antes de você
instalar ou confiar.

> Alvo diferente de um scanner de aplicação: este não audita o app que você publicou, e sim
> o material que o **seu agente** carrega e obedece.

## Instalar

- **Claude Code:** `npx skills add robertodiasduarte/rdd-audita-harness -a claude-code -y` (instala em `.claude/skills/` do projeto; com `-g`, em `~/.claude/skills/`).
- **Codex:** `npx skills add robertodiasduarte/rdd-audita-harness -a codex -y` (instala em `.agents/skills/` do projeto; com `-g`, em `~/.agents/skills/`, que o Codex também lê).
- **Cursor, Kimi e outros:** mesmo comando com o nome do agente em `-a`. Sem Node.js, descompacte o `.zip` e copie a pasta `rdd-audita-harness/` para o diretório de skills do seu agente.

O `.zip` da [Release mais recente](../../releases/latest) continua disponível para instalar
no claude.ai e no ChatGPT, sem descompactar.

## Usar

```bash
# harness do Claude Code
python3 scripts/auditar.py ~/.claude/skills ~/.claude/agents ~/.claude/settings.json ~/.claude/hooks

# harness do Codex — config.toml, rules, hooks e as 3 pastas de skills
python3 scripts/auditar.py ~/.codex/config.toml ~/.codex/rules ~/.codex/hooks.json \
    ~/.codex/skills ~/.agents/skills ~/.codex/AGENTS.md

# no projeto, os dois de uma vez
python3 scripts/auditar.py .claude .codex .agents/skills AGENTS.md .mcp.json

# camada C3 — capacidade x proposito, pega payload em LINGUAGEM NATURAL
python3 scripts/auditar.py ~/Downloads/skill-nova/ --dossie
```

**Codex precisa ler TOML.** No Python 3.11+ isso é nativo. Em versões anteriores, instale
`pip3 install tomli` — sem nenhum dos dois o auditor **avisa** que não leu o `config.toml`
e sai com erro, em vez de dar verde sobre um arquivo que não abriu.

`exit 0` = nada grave · `exit 1` = achado HIGH/CRITICAL · `--json` para integrar.

**`--dossie`** emite o material neutralizado para o agente que carregou a skill julgar —
custo zero, sem chave de API, porque a skill ja roda dentro de um LLM. **`--c3`** faz a
chamada direta (para CI/lote, sem agente na frente). Sem nenhum dos dois, o auditor e
100% deterministico e cego para o payload em linguagem natural.

## Por que existe

A Snyk varreu 3.984 skills públicas (fev/2026): **36,8% com ≥1 falha, 13,4% críticas, 76
com payload malicioso confirmado** — e **91% das maliciosas combinam instrução enganosa com
código malicioso**. Duas propriedades derrotam a revisão a olho: o payload dominante é
**linguagem natural** (scanner só de código erra a maior parte) e **unicode invisível** muda
o que o modelo lê sem mudar o que você vê.

Por isso a camada determinística converte todo caractere não-ASCII em hex **antes** de
qualquer leitura por IA — senão o próprio auditor obedeceria o payload.

## Ressalva

**Scan limpo não prova que a skill é benigna.** Cobrimos padrões conhecidos e a coerência
entre capacidade e propósito declarado. Ausência de achado é ausência de evidência.

## Skills irmãs

- [rdd-appsec-mentor](https://github.com/robertodiasduarte/rdd-appsec-mentor) — o que ficou exposto no app que você criou
- [rdd-detecta-invasao](https://github.com/robertodiasduarte/rdd-detecta-invasao) — quem está operando a sua conta

## Licença

MIT — ver [LICENSE](LICENSE).
