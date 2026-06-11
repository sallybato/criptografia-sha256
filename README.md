# SHA-256

Implementação do algoritmo SHA-256 do zero em Python, sem bibliotecas de criptografia.

Este repositório contém dois programas independentes que utilizam a mesma implementação do SHA-256:

---

## Arquivos

| Arquivo | Descrição |
|---|---|
| `sha256.py` | Implementação pura do SHA-256 |
| `verificador.py` | Autenticador de arquivos usando o SHA-256 |
| `teste.txt` | Arquivo de exemplo para testes |

> Os dois programas são independentes e estão na mesma pasta por compartilharem o mesmo contexto da disciplina.

---

## sha256.py — SHA-256 Puro

Implementação completa do algoritmo SHA-256 do zero, seguindo as 4 etapas do padrão:

1. **Padding** — ajusta o tamanho da mensagem para múltiplo de 512 bits
2. **Message Schedule** — expande o bloco de 16 para 64 palavras
3. **Compressão** — aplica 64 rodadas de mistura com as constantes K
4. **Digest** — concatena o estado final em hexadecimal

### Como rodar

```
python sha256.py
```

O programa pede um texto e retorna o hash SHA-256 correspondente.

**Exemplo:**
```
Digite o texto: hello world
Hash SHA-256: b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576e141b1b4a867ab7
```

---

## verificador.py — Autenticador de Arquivos

Aplicação que utiliza a implementação do SHA-256 para autenticar arquivos de qualquer formato.

**Funcionalidades:**
- Gera o hash SHA-256 de um arquivo e salva em um `.sha256`
- Verifica se um arquivo é autêntico comparando com um hash fornecido
- Detecta qualquer alteração no arquivo, por menor que seja

### Como rodar

```
python verificador.py
```

Abre o menu interativo com duas opções:

**Opção 1 — Gerar hash:**
```
Opção: 1
Caminho do arquivo: teste.txt
```
O programa gera o hash e salva em `teste.txt.sha256`.

**Opção 2 — Verificar autenticidade:**
```
Opção: 2
Caminho do arquivo: teste.txt
Hash SHA-256 esperado: <cole o hash aqui>
```
O programa informa se o arquivo é autêntico ou foi alterado.

### Demonstração completa

1. Gera o hash do `teste.txt` com a opção 1
2. Verifica com a opção 2 usando o hash gerado → **ARQUIVO AUTÊNTICO**
3. Abre o `teste.txt`, altera qualquer caractere e salva
4. Verifica novamente com o mesmo hash → **ARQUIVO INVÁLIDO**

---

## Bibliotecas utilizadas

| Biblioteca | Uso |
|---|---|
| `struct` | Empacotamento de bytes para manipulação binária |
| `os` | Leitura de metadados do arquivo (nome, tamanho) |
| `sys` | Leitura de argumentos da linha de comando |

> Nenhuma biblioteca de criptografia foi utilizada. O algoritmo SHA-256 é implementado inteiramente do zero.
