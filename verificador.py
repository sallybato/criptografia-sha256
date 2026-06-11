import sys
import os
import struct


# SHA-256 — implementação do zero


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def gamma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def pad_message(message: bytes) -> bytes:
    length_bits = len(message) * 8
    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'
    message += struct.pack('>Q', length_bits)
    return message

def message_schedule(block: bytes) -> list:
    w = list(struct.unpack('>16I', block))
    for i in range(16, 64):
        w.append(
            (gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16]) & 0xFFFFFFFF
        )
    return w

def compress(state: list, w: list) -> list:
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
        t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
        h = g; g = f; f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c; c = b; b = a
        a = (t1 + t2) & 0xFFFFFFFF
    return [(x + y) & 0xFFFFFFFF for x, y in zip([a, b, c, d, e, f, g, h], state)]

def sha256(data: bytes) -> str:
    padded = pad_message(data)
    state = H_INIT[:]
    for i in range(0, len(padded), 64):
        state = compress(state, message_schedule(padded[i:i+64]))
    return ''.join(f'{h:08x}' for h in state)

def formatar_tamanho(n: int) -> str:
    for u in ['B', 'KB', 'MB', 'GB']:
        if n < 1024:
            return f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def ler_arquivo(filepath: str) -> bytes:
    """Lê qualquer arquivo em modo binário."""
    with open(filepath, 'rb') as f:
        return f.read()

def validar_hash(hash_str: str) -> bool:
    """Verifica se a string é um hash SHA-256 válido (64 chars hex)."""
    return len(hash_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in hash_str)

def separador(char='─', largura=60):
    print(char * largura)

def cabecalho(titulo: str):
    separador('═')
    print(f"  {titulo}")
    separador('═')

def info_arquivo(filepath: str):
    nome     = os.path.basename(filepath)
    extensao = os.path.splitext(nome)[1] or "(sem extensão)"
    tamanho  = os.path.getsize(filepath)
    print(f"  Arquivo  : {nome}")
    print(f"  Formato  : {extensao}")
    print(f"  Tamanho  : {formatar_tamanho(tamanho)}")


#gerar hash abaixo
def gerar_hash(filepath: str):
    """Lê o arquivo e imprime o hash SHA-256."""

    cabecalho("GERAR HASH SHA-256")

    if not os.path.isfile(filepath):
        print(f"\n  X Arquivo não encontrado: {filepath}\n")
        return

    info_arquivo(filepath)
    separador()

    print("  Calculando SHA-256...", end=" ", flush=True)
    data        = ler_arquivo(filepath)
    hash_result = sha256(data)
    print("pronto!\n")

    print("  Hash SHA-256:")
    print(f"  {hash_result}\n")

    # Salva o hash em um arquivo .sha256 ao lado do original
    hash_file = filepath + ".sha256"
    with open(hash_file, 'w') as f:
        f.write(hash_result)

    print(f"  Hash salvo em: {os.path.basename(hash_file)}")
    separador('═')


# funcionalidade para verificar a autenticidade

def verificar_autenticidade(filepath: str, hash_esperado: str):

    cabecalho("VERIFICAR AUTENTICIDADE")

    if not os.path.isfile(filepath):
        print(f"\n  X Arquivo não encontrado: {filepath}\n")
        return

    hash_esperado = hash_esperado.strip().lower()

    if not validar_hash(hash_esperado):
        print(f"\n  X Hash inválido. Deve ter 64 caracteres hexadecimais.\n")
        return

    info_arquivo(filepath)
    separador()

    print("  Calculando SHA-256...", end=" ", flush=True)
    data         = ler_arquivo(filepath)
    hash_atual   = sha256(data)
    print("pronto!\n")

    print(f"  Hash fornecido : {hash_esperado}")
    print(f"  Hash do arquivo: {hash_atual}")
    separador()

    if hash_atual == hash_esperado:
        print("  ARQUIVO AUTÊNTICO")
        print("  Os hashes coincidem. O arquivo não foi alterado.")
    else:
        print("  ARQUIVO INVÁLIDO")
        print("  Os hashes divergem. O arquivo foi adulterado ou corrompido.")

        # Mostra quais posições do hash diferem
        diffs = [i for i in range(64) if hash_atual[i] != hash_esperado[i]]
        print(f"  Divergências em {len(diffs)} de 64 posições do hash.")

    separador('═')

#menu interativo
def menu():
    cabecalho("VERIFICADOR DE AUTENTICIDADE — SHA-256")
    print("""
  Escolha uma operação:

    1. Gerar hash SHA-256 de um arquivo
    2. Verificar autenticidade de um arquivo
    0. Sair
""")

def pedir_arquivo() -> str:
    path = input("  Caminho do arquivo: ").strip().strip('"').strip("'")
    return path

def pedir_hash() -> str:
    return input("  Hash SHA-256 esperado: ").strip()


def main():
    
    if len(sys.argv) >= 3:
        modo    = sys.argv[1].lower()
        arquivo = sys.argv[2]

        if modo in ('gerar', 'g'):
            gerar_hash(arquivo)

        elif modo in ('verificar', 'v') and len(sys.argv) == 4:
            verificar_autenticidade(arquivo, sys.argv[3])

        else:
            print("\n  Uso:")
            print("    python verificador.py gerar <arquivo>")
            print("    python verificador.py verificar <arquivo> <hash>\n")
        return


    while True:
        menu()
        opcao = input("  Opção: ").strip()

        if opcao == '1':
            print()
            arquivo = pedir_arquivo()
            print()
            gerar_hash(arquivo)

        elif opcao == '2':
            print()
            arquivo = pedir_arquivo()
            hash_   = pedir_hash()
            print()
            verificar_autenticidade(arquivo, hash_)

        elif opcao == '0':
            print("\n  Até mais!\n")
            break

        else:
            print("\n  Opção inválida. Tente novamente.\n")

        input("\n  [Enter para continuar]")
        print()


if __name__ == '__main__':
    main()