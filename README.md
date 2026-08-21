# rdd-audita-harness

Skill que audita **o que a sua IA executa** — skills, agentes, comandos, hooks e servidores
MCP — procurando easter eggs, código malicioso, backdoors e exfiltração, antes de você
instalar ou confiar.

> Alvo diferente de um scanner de aplicação: este não audita o app que você publicou, e sim
> o material que o **seu agente** carrega e obedece.

## Instalar

Baixe o `.zip` da [Release mais recente](../../releases/latest) e descompacte em
`~/.claude/skills/` (ou na pasta de skills da sua ferramenta).

## Usar

```bash
python3 scripts/auditar.py ~/.claude/skills ~/.claude/agents ~/.claude/settings.json
```

`exit 0` = nada grave · `exit 1` = achado HIGH/CRITICAL · `--json` para integrar.

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
