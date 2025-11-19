# CipherVault – Protótipo (v1.3.0)

Aplicação CLI mínima para cifrar/decifrar um único ficheiro para uso próprio utilizando RSA-4096 + AES-256-GCM. Inclui gestão local de contactos (nome + chave pública) para futura partilha.

## Pré-requisitos

- Python 3.10+
- Windows PowerShell (fornecido) ou outro terminal

## Instalação

1) Criar/ativar um ambiente virtual (opcional mas recomendado)
2) Instalar dependências:

```
pip install -r requirements.txt
```

## Executar o Protótipo

Menu interativo (cifrar/decifrar):

```
python src/main.py
```

Comandos diretos:

```
# Cifrar para si
python src/main.py encrypt <caminho_ficheiro>

# Decifrar ficheiro .cvault
python src/main.py decrypt <caminho_ficheiro.cvault>

# Ver chaves e impressões digitais
python src/main.py --debug keys

# Mostrar versão
python src/main.py --version

# Ver chave pública
python src/main.py public-key

# Contactos (gestão local)
python src/main.py contacts-list
python src/main.py contacts-add --name "NOME" --pubkey "caminho/para/public.pem"
python src/main.py contacts-delete --name "NOME"
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

Versão atual: 1.3.0 (Contactos: adicionar/listar/apagar; removida visualização de chave privada; docs PT-PT).

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
