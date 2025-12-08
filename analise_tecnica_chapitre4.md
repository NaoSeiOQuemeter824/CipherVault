# Análise Técnica para o Capítulo 4 (Resultados e Análise)

## 4.1 Performance e Otimização (Gestão de Memória)

**Análise do Código Atual:**
Ao analisar o método `encrypt_file` em `src/ciphervault/crypto.py`, verificamos que a implementação atual **não utiliza chunking** (fragmentação). O ficheiro é lido integralmente para a memória RAM numa única operação:

```python
data = input_path.read_bytes()  # Lê todo o ficheiro para a RAM
# ...
ciphertext = encryptor.update(data) + encryptor.finalize()
```

**Impacto Técnico:**
*   **Velocidade:** Para ficheiros pequenos e médios (ex: documentos, imagens), esta abordagem é extremamente rápida pois evita o overhead de I/O repetitivo.
*   **Limitação:** O tamanho máximo do ficheiro cifrável está limitado pela RAM disponível no sistema. Se o utilizador tentar cifrar um ficheiro de 10GB numa máquina com 8GB de RAM, o processo falhará com `MemoryError`.
*   **Nota para o Relatório:** Deve ser mencionado como uma decisão de design para o protótipo v1.5.0 (foco na simplicidade e integridade atómica), com a implementação de `CHUNK_SIZE` (ex: 64KB) planeada para a v2.0 para suportar ficheiros gigantes (streaming encryption).

## 4.2 Análise do Comando 'Verify' (Opção 6)

O comando `verify_authenticity` executa um processo de validação em profundidade, mas otimizado para não escrever no disco.

**Fluxo de Execução (Step-by-Step):**
1.  **Leitura do Cabeçalho:** O código lê apenas os primeiros bytes para extrair os metadados (JSON) e as chaves, sem processar o corpo cifrado imediatamente.
2.  **Verificação de Integridade (AES-GCM):**
    *   O sistema decifra a chave AES (usando RSA).
    *   O sistema processa todo o `ciphertext` através do algoritmo AES-GCM.
    *   **Ponto Crítico:** O GCM verifica o `Tag` (16 bytes) no final. Se um único bit do ficheiro cifrado tiver sido alterado, o cálculo do Tag falha.
3.  **Verificação de Autenticidade (RSA-PSS):**
    *   Apenas **após** a integridade técnica ser validada (Tag OK), o sistema calcula o Hash SHA-256 do plaintext recuperado em memória.
    *   Este Hash é comparado com a assinatura digital RSA-PSS do remetente.

**Justificação de Performance:**
A verificação é rápida porque ocorre inteiramente em memória (`RAM`), sem o custo de I/O de escrever o ficheiro decifrado no disco rígido. O plaintext é descartado imediatamente após a verificação do Hash.

## 4.3 Robustez e Gestão de Erros de Segurança

A biblioteca `cryptography` utiliza exceções específicas para garantir que falhas de segurança não passem despercebidas.

**Exceção Identificada:**
Quando o Tag de autenticação GCM não corresponde (indicando ficheiro corrompido ou ataque de adulteração), a biblioteca não retorna `False`, ela levanta uma exceção:

*   **Nome da Exceção:** `cryptography.exceptions.InvalidTag` (embora no código atual seja capturada genericamente como `Exception` para evitar crash da CLI, internamente é este o mecanismo).

**Evidência no Código (`cli.py`):**
O código captura estas falhas e traduz para uma mensagem de alerta crítica:

```python
if "tag mismatch" in msg.lower():
    console.print("[red]O ficheiro .cvault está corrompido ou foi adulterado.[/red]")
```

Isto prova que o sistema distingue entre um "erro de ficheiro não encontrado" e um "erro de segurança criptográfica".
