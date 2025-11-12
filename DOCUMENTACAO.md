# CipherVault – Documentação do Protótipo (v1.1.0)

Este documento descreve o que foi implementado no primeiro protótipo e as próximas evoluções possíveis.

## Objetivo

- Disponibilizar uma aplicação de linha de comandos simples
- Permitir selecionar um ficheiro (ex.: arquivo .zip/.rar para pastas, imagens ou qualquer ficheiro)
- Cifrar/Decifrar apenas para o próprio (sem partilha ainda) via cifragem híbrida

## Arquitetura

- RSA-4096 (assimétrico) + AES-256-GCM (simétrico)
- Formato de contentor único: `.cvault`
- Armazenamento das chaves: `~/.ciphervault/` (chave privada + chave pública)

### Fluxo de Cifragem (cifrar para si)

1. Gerar chave AES aleatória de 256 bits + nonce GCM de 96 bits
2. Cifrar o conteúdo com AES-256-GCM (confidencialidade + integridade via tag)
3. Cifrar a chave AES com a chave pública RSA-4096 do utilizador (OAEP/SHA-256)
4. Assinar o hash SHA-256 do conteúdo original com a chave privada (RSA-PSS)
5. Escrever o ficheiro `.cvault` contendo metadados + chave pública + chave AES cifrada + assinatura + nonce + tag + ciphertext

### Fluxo de Decifragem

1. Verificar o formato `.cvault`
2. Verificar que a chave pública embutida corresponde realmente à do utilizador local
3. Decifrar a chave AES com a chave privada
4. Decifrar o conteúdo AES-256-GCM (falha se tag inválida ⇒ conteúdo corrompido)
5. Verificar a assinatura (RSA-PSS) sobre o conteúdo decifrado
6. Escrever o ficheiro original

## Estrutura de Diretórios

```
src/
  ciphervault/
    __init__.py
    crypto.py      # lógica criptográfica: gestão de chaves, cifrar/decifrar
    cli.py         # interface CLI mínima (interativo + comandos cifrar/decifrar)
  main.py          # ponto de entrada `python src/main.py`

DOCUMENTACAO.md     # este documento
README.md           # instruções de execução
requirements.txt    # dependências
```

## Opções Técnicas

- RSA-4096 + OAEP(SHA-256) para envolver a chave AES
- AES-256-GCM para cifrar dados e garantir integridade (tag 16 bytes)
- Assinatura RSA-PSS (SHA-256) para autenticar o autor e detetar alteração
- Sem compressão automática: para cifrar uma pasta o utilizador cria primeiro um `.zip` ou `.rar`

## Limitações Atuais (v1.1.0)

- Sem interface gráfica: apenas CLI
- Sem opções avançadas: fluxo básico cifrar/decifrar para si
- Pastas não suportadas diretamente (usar .zip/.rar manualmente)
- Ainda sem modo "para destinatário" nem "assinatura apenas"

## Próximos Passos Sugeridos

- Adicionar modo "para destinatário" (chave pública externa) e multi-destinatários
- Adicionar modo "assinatura apenas" para partilha pública autenticada
- Personalização de caminhos de saída e validações adicionais
- Detetar automaticamente tipos de ficheiros (imagens, arquivos) para melhor UX
- Empacotar CLI (entry point) e criar binário executável

## Segurança – Resumo

- Confidencialidade: AES-256-GCM
- Integridade: Tag GCM + verificação de assinatura
- Autenticidade: Assinatura RSA-PSS sobre hash do conteúdo original

## Notas de Versão

- 1.0.1: Logs de debug, comando `keys`, versão exposta na CLI
- 1.1.0: Tradução completa da documentação e comentários para PT-PT

## Próximos Incrementos de Versão

- Patch (ex.: 1.1.1): pequenas melhorias
- Minor (ex.: 1.2.0): novas funcionalidades compatíveis (ex.: modo destinatário)
- Major (ex.: 2.0.0): mudanças potencialmente incompatíveis (novo formato .cvault)

---

Se precisar de detalhes adicionais teóricos ou provas de conceito de outros modos (multi-recipient, streaming), podemos expandir em documentos separados.
