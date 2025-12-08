# CipherVault – Protótipo (v1.6.0)

Aplicação CLI robusta para cifrar, decifrar e verificar ficheiros, utilizando criptografia híbrida (RSA-4096 + AES-256-GCM). Permite o uso pessoal e a partilha segura com contactos. Inclui gestão de chaves, exportação de chave pública e cifragem direcionada a destinatários específicos. 

**Novo em 1.6.0:** Smart Launcher com atualização automática (verifica GitHub), gestão automática de ambiente virtual e dependências, e proteção contra downgrade.

## Pré-requisitos

- Python 3.10+
- Windows PowerShell (fornecido) ou outro terminal
- Ligação à Internet (para atualizações automáticas)

## Instalação e Execução Rápida

A partir da versão 1.6.0, o **Smart Launcher** trata de tudo (ambiente virtual, dependências e atualizações).

Basta executar o ficheiro de comando:

```cmd
.\ciphervault.cmd
```

O launcher irá:
1. Verificar/Criar o ambiente virtual (`.venv`).
2. Instalar/Atualizar dependências (`requirements.txt`).
3. Verificar se existe uma nova versão no GitHub e atualizar automaticamente.
4. Iniciar a aplicação.

## Executar Manualmente (Avançado)

Se preferir não usar o launcher:

1) Criar o ambiente virtual:
   ```
   python -m venv .venv
   ```

2) Ativar o ambiente virtual:
   ```
   .\.venv\Scripts\Activate.ps1
   ```

3) Instalar dependências:
   ```
   pip install -r requirements.txt
   ```

4) Executar:
   ```
   python src/main.py
   ```

## Comandos Disponíveis

```
# Cifrar para si
python src/main.py encrypt <caminho_ficheiro>

# Decifrar ficheiro .cvault
python src/main.py decrypt <caminho_ficheiro.cvault>

# Verificar autenticidade, integridade e metadados (Relatório de Segurança)
python src/main.py verify <caminho_ficheiro.cvault>

# Ver chaves e impressões digitais
python src/main.py --debug keys

# Mostrar versão
python src/main.py --version

# Ver chave pública no terminal
python src/main.py public-key

# Exportar a minha chave pública para ficheiro PEM (partilha)
python src/main.py export-public-key --out "C:\\Users\\Tu\\Documents\\CipherVault_public_key.pem"

# Contactos (gestão local)
python src/main.py contacts-list
python src/main.py contacts-add --name "NOME" --pubkey "caminho/para/public.pem"
python src/main.py contacts-delete --name "NOME"

# Cifrar para um contacto (usa a chave pública do contacto)
python src/main.py encrypt-for-contact <caminho_ficheiro> --name "NOME"
```

Notas:
- Para cifrar uma pasta, comprima primeiro em .zip ou .rar e depois cifre o arquivo resultante.
- As chaves são guardadas em: %USERPROFILE%\.ciphervault\ (chave privada e pública)
- Modo debug: adicione `--debug` antes do comando (ex.: `python src/main.py --debug encrypt ...`) para ver registos detalhados (geração/carregamento de chaves, etapas de cifragem/decifragem).

## Versionamento

- Formato: MAIOR.MENOR.CORRETIVO (ex.: 1.1.0)
- Regras:
  - Corretivo (+0.0.1): pequenas melhorias, registos, correções
  - Menor (+0.1.0): novas funcionalidades compatíveis (ex.: novo comando)
  - Maior (+1.0.0): alterações importantes/incompatíveis

Versão atual: 1.6.0 (Smart Launcher, Auto-update, Anti-downgrade, Correções de interface).

## Segurança (Resumo)

- Dados: AES-256-GCM (confidencialidade + integridade via tag)
- Chave: envolvida com RSA-4096 OAEP (SHA-256)
- Assinatura: RSA-PSS (SHA-256) sobre conteúdo original

Para mais teoria, consultar `DOCUMENTACAO.md`.

## Abrir uma janela CMD dedicada (Windows)

Pode lançar uma janela própria do CipherVault com opções visíveis e arranque em modo interativo:

```
./ciphervault.cmd
```

Notas:
- Se existir `.venv\Scripts\python.exe`, será usado automaticamente; caso contrário usa `python` do sistema.
- O script mostra `--version`, depois `--help`, exemplos de contactos e arranca o modo interativo.
- No fim, a janela pede uma tecla para fechar.
