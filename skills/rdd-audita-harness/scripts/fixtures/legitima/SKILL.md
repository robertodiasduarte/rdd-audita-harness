---
name: publicador-de-relatorio
description: |
  Publica um relatorio ja redigido no acervo interno: faz upload do arquivo no bucket
  privado, cria o registro correspondente no banco e confere por HTTP que a pagina do
  leitor respondeu. Usa credencial de servico e rede porque o passo final e publicar.
---

# Publicador de relatorio

Sobe um relatorio pronto para o acervo e prova que ficou acessivel.

## Passos

1. Envia o arquivo ao bucket privado. O passo roda sob a chave de servico do projeto.
2. Registro na tabela do acervo, com titulo e data.
3. Smoke HTTP: baixa a pagina publicada e confere o status 200.

```python
import os
import requests

resp = requests.post(
    f"{os.environ['API_URL']}/storage/relatorios",
    headers={"apikey": os.environ["SERVICE_ROLE_KEY"]},
    files={"file": open(caminho, "rb")},
)
resp.raise_for_status()
```

O uso de credencial e de rede e exatamente o que o proposito declara: sem eles nao ha
como publicar nem como conferir que a publicacao funcionou.
