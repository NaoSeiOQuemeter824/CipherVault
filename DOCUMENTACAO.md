# CipherVault – Documentação Completa do Protótipo (v1.3.0)

Este documento central reúne numa só referência tudo o que é necessário para
compreender, explicar e justificar o funcionamento do protótipo CipherVault.
Inclui: objetivos, arquitetura, formato de ficheiro, fluxo interno, código
organizado por módulos, comandos CLI, segurança, limitações e roadmap.

## Objetivo

- Fornecer uma aplicação simples de linha de comandos para proteger ficheiros locais.
- Cifrar e decifrar apenas “para o próprio” (self) na versão 1.3.0.
- Usar uma abordagem criptográfica moderna e segura (híbrida: simétrica + assimétrica).
- Manter um formato de contentor único (`.cvault`) auto‑descritivo.
- Facilitar futura evolução para multi-destinatários e funcionalidades adicionais.
 - Gerir contactos (nome + chave pública) localmente para futura partilha.

## Arquitetura

- Criptografia híbrida: RSA-4096 (assimétrico) + AES-256-GCM (simétrico).
- Controlo de autenticidade: assinatura RSA-PSS sobre hash SHA-256 do conteúdo original.
- Contentor `.cvault`: inclui metadados, chave pública, chave AES envolvida, assinatura, nonce, tag e ciphertext.
- Armazenamento local das chaves: `~/.ciphervault/` contendo `private_key.pem` e `public_key.pem`.
- Código organizado em módulos (`crypto.py` para operações de baixo nível, `cli.py` para interface e fluxo de utilização).

### Fluxo de Cifragem (“para mim”)

1. Ler o ficheiro original (plaintext).
2. Gerar chave AES-256 aleatória (32 bytes) e nonce GCM (12 bytes).
3. Cifrar o plaintext com AES-256-GCM → produz ciphertext + tag de integridade.
4. Envolver a chave AES com a chave pública RSA-4096 do utilizador (OAEP/SHA-256).
5. Calcular hash SHA-256 do plaintext e assinar com a chave privada (RSA-PSS).
6. Construir e escrever o ficheiro `.cvault` com a estrutura definida.

### Fluxo de Decifragem

1. Ler e validar cabeçalho (`Magic`, versão, flags).
2. Recuperar metadados e chave pública embutida.
3. Confirmar que a chave pública do contentor coincide com a chave local (garante que foi cifrado “para mim”).
4. Decifrar a chave AES com a chave privada (RSA-OAEP).
5. Decifrar dados com AES-256-GCM (verificando a tag de integridade).
6. Recalcular hash do plaintext e verificar assinatura RSA-PSS.
7. Escrever ficheiro restaurado.

Se qualquer verificação falhar (tag ou assinatura), o processo termina com erro.

### Estrutura Binária do Contentor `.cvault`

| Ordem | Campo | Tamanho | Descrição |
|-------|-------|---------|-----------|
| 1 | Magic | 6 | `CVAULT` identificação|
| 2 | Versão | 1 | Versão de formato |
| 3 | Flags | 1 | bit0=1 cifrado (reserva futura) |
| 4 | Meta_len | 2 | uint16 tamanho do JSON |
| 5 | Metadados | n | JSON `{filename,size}` |
| 6 | Pub_len | 2 | uint16 tamanho PEM chave pública |
| 7 | PubKey PEM | n | Chave pública do autor |
| 8 | AES_wrap_len | 2 | uint16 tamanho chave AES envolvida |
| 9 | AES_wrapped | n | Chave AES cifrada RSA-OAEP |
|10 | Sig_len | 2 | uint16 tamanho assinatura |
|11 | Assinatura | n | RSA-PSS(SHA-256) sobre plaintext |
|12 | Nonce | 12 | Nonce GCM (96 bits) |
|13 | Tag | 16 | Tag GCM (integridade simétrica) |
|14 | Ciphertext | resto | Dados cifrados |

Racional: formato direto facilita debugging e futura migração para cabeçalho
opaco (ex.: DER/CBOR) sem perder legibilidade interna do protótipo.

## Estrutura de Diretórios e Papéis

```
src/
  ciphervault/
    __init__.py      -> expõe __version__
    crypto.py        -> operações criptográficas (KeyStore, SelfEncryptor)
    contacts.py      -> gestão de contactos (persistência JSON, validação PEM)
    cli.py           -> interface CLI (menu interativo + comandos diretos)
  main.py            -> ponto de entrada simplificado

ciphervault.cmd      -> lançador Windows (abre menu persistente)
DOCUMENTACAO.md      -> documentação completa (este ficheiro)
README.md            -> instruções rápidas de uso
requirements.txt     -> lista de dependências Python
```

### Módulo `crypto.py`
- `KeyStore`: garante existência e carregamento das chaves, gera fingerprint.
- `SelfEncryptor`: implementa cifrar e decifrar para o próprio; constrói/parceia o formato.

### Módulo `cli.py`
- Grupo principal Click: parse de opções, ativação de debug.
- Função `_interactive`: loop de menu (1. cifrar 2. decifrar 3. ver chave pública 4. contactos 5. sair).
- Comandos individuais: `encrypt`, `decrypt`, `keys`, `public-key`, `contacts-list`, `contacts-add`, `contacts-delete`.
- Auxiliares: normalização de caminhos, visualização de PEM (apenas pública) e fluxos de contactos.

### Módulo `contacts.py`
- `ContactsStore`: armazena contactos em `~/.ciphervault/contacts.json`.
  - Cada contacto contém: `name`, `public_pem` (PEM), `fingerprint` (SHA-256 em hex do PEM).
  - Valida se o PEM fornecido é uma chave pública válida.
  - Operações: `add_contact`, `list_contacts`, `delete_contact`.

### `main.py`
- Proxy para `cli()` permitindo `python src/main.py`.

### `ciphervault.cmd`
- Conveniência Windows: abre consola separada e inicia modo interativo.
- Mostra versão, ajuda, e exemplos rápidos incluindo comandos de contactos.

## Opções Técnicas e Justificação

- RSA-4096 OAEP(SHA-256): segurança contra ataques de padding e robustez futura.
- AES-256-GCM: padrão industrial (AEAD) evitando necessidade separada de HMAC.
- RSA-PSS (SHA-256): assinatura moderna com randomização, mitigando ataques de forja.
- Fingerprint SHA-256: identificação humana rápida; pode evoluir para ID truncado etiquetado.
- PEM para chave pública: legibilidade e interoperabilidade; poderá migrar para DER (opacidade) em versão 1.2.x.
- Sem compressão automática: reduz complexidade; utilizador controla compressão (zip/rar) conforme necessidade.

## Limitações Atuais (v1.3.0)

- Apenas modo “self” (sem destinatários externos).
- Cabeçalho parcialmente legível (inclui PEM) – melhoria futura: versão opaca.
- Não suporta cifragem de múltiplos ficheiros em lote num único contentor.
- Chave privada sem proteção adicional (ex.: password / hardware token).
- Não há verificação de revogação/rotação automática de chaves.
 - Contactos servem apenas para gestão local; não há envio/cifragem para contactos nesta versão.

## Roadmap Proposto

### 1.2.x (Incremental)
- Cabeçalho binário opaco (DER/CBOR) ou substituição PEM por fingerprint.
- Opção de saída personalizada (`--out` / escolha no menu).
- Modo “ver detalhes” do contentor (inspeção sem decifrar total).

### 1.3.0 (Funcionalidade Nova)
- Gestão de contactos local (adicionar/listar/apagar) com validação do PEM público e fingerprint.
- Remoção da visualização de chave privada no CLI (redução de superfície de risco).

### 1.4.0 (Planeado)
- Multi-destinatários: vários blocos de chave AES envolvida (um por chave pública).
- Flag `--also-me` para incluir o remetente como destinatário explícito.
- Comando para adicionar novo destinatário a contentor existente (re-envelopar chave AES).

### 1.5.x
- Modo assinatura apenas (gerar ficheiro + assinatura separada .sig).
- Integração opcional com hash de diretórios e manifestos.

### 2.0.0 (Potencial)
- Reformulação do formato com estrutura escalável (TLV / CBOR com índice).
- Rotação de chaves e metadados de política (algoritmos permitidos, expiração).

## Segurança – Resumo Executivo

- Confidencialidade: AES-256-GCM protege o conteúdo.
- Integridade: Tag GCM + assinatura RSA-PSS (dupla verificação: simétrica e assimétrica).
- Autenticidade: Garantida pela assinatura do plaintext (origem + não alteração).

### Detalhe dos Primitivos
- AES-256-GCM: modo AEAD; nonce único por cifragem (12 bytes). Reutilização de nonce com mesma chave é perigosa – mitigado pela geração aleatória.
- RSA-OAEP: adiciona máscara (MGF1) e digest para prevenir ataques de texto escolhido.
- RSA-PSS: usa salt aleatório, evitando determinismo e aumentando resistência a ataques.
- SHA-256: equilibrado entre segurança e ubiquidade.

### Superfície de Ataque e Mitigações
- Exposição da chave privada ⇒ comprometimento total. Mitigação futura: password / HSM.
- Modificação do contentor ⇒ assinatura ou tag falham (detetado).
- Colisões intencionais de fingerprint (SHA-256) são impraticáveis com recursos normais.

## Notas de Versão

- 1.0.1: Logs de debug, comando `keys`, versão CLI.
- 1.1.0: Tradução inicial documentação e mensagens PT-PT.
- 1.2.0: Menu interativo persistente; lançador `ciphervault.cmd`.
- 1.2.1: Visualização de chave pública/privada via menu e comandos (`public-key`, `private-key`) + comentários detalhados no código.
- 1.3.0: Contactos (adicionar/listar/apagar); remoção de visualização da chave privada; atualização de CLI e lançador.

## Esquema de Versionamento

- Patch (x.y.Z): correções e melhorias pequenas sem alterar formato.
- Minor (x.Y.z): novas funcionalidades compatíveis (ex.: multi-destinatários, cabeçalho opaco).
- Major (X.y.z): mudanças de formato ou quebra de compatibilidade (ex.: estrutura binária radicalmente diferente).

## FAQ Rápida

**Porque é visível a chave pública no contentor?**
Facilita verificação e não prejudica segurança; apenas a chave privada permite decifrar.

**Porque assinar o plaintext e não o ciphertext?**
Assinar o plaintext torna explícita a integridade do conteúdo original e evita dependência do modo simétrico para autenticação completa.

**Posso partilhar .cvault atual com outra pessoa?**
Não; só contém a chave pública do autor. Precisará de versão multi-destinatários.

**O que acontece se alterar um byte do ficheiro?**
Tag GCM ou assinatura falham – o processo acusa corrupção.

**Posso cifrar pastas diretamente?**
Não; comprima primeiro (zip/rar) para obter um único ficheiro.

**Para que servem os Contactos nesta versão?**
Apenas para gerir localmente chaves públicas de terceiros (validadas e com fingerprint). A cifragem para contactos não está ainda disponível.

---

---

Para detalhes adicionais (multi-destinatários, cabeçalhos binários, integração
com manifestos ou assinatura isolada) evoluir conforme roadmap descrito.
