import struct
import math


# ============================================================
# CONSTANTES DO SHA-256
# ============================================================

# As primeiras 32 bits das raízes cúbicas dos primeiros 64 números primos.
# Usadas em cada uma das 64 rodadas de compressão.
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

# Os valores iniciais de hash H0–H7.
# São as primeiras 32 bits das raízes quadradas dos primeiros 8 números primos.
H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]


# ============================================================
# FUNÇÕES AUXILIARES DE BITS
# ============================================================

def rotr(x, n):
    """Rotação circular à direita de n bits em um valor de 32 bits."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    """Choose: onde x=1, escolhe y; onde x=0, escolhe z."""
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    """Majority: retorna o bit majoritário entre x, y, z."""
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    """Σ0: mistura de rotações usada no estado de compressão."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1(x):
    """Σ1: mistura de rotações usada no estado de compressão."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def gamma0(x):
    """σ0: usada na expansão do schedule de mensagem."""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def gamma1(x):
    """σ1: usada na expansão do schedule de mensagem."""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


# ============================================================
# ETAPA 1: PADDING
# ============================================================

def pad_message(message: bytes) -> bytes:
    """
    Adiciona padding à mensagem para que seu tamanho seja
    múltiplo de 512 bits (64 bytes).

    Estrutura do padding:
      [mensagem original] [bit 1] [zeros] [tamanho original em 64 bits]
    """
    length_bits = len(message) * 8          # tamanho original em bits
    message += b'\x80'                      # adiciona o bit '1' (0x80 = 10000000)

    # Adiciona zeros até restar 8 bytes (64 bits) para o bloco de 64 bytes
    while len(message) % 64 != 56:
        message += b'\x00'

    # Adiciona o tamanho original como inteiro de 64 bits big-endian
    message += struct.pack('>Q', length_bits)

    return message


# ============================================================
# ETAPA 2: EXPANSÃO DO SCHEDULE DE MENSAGEM
# ============================================================

def message_schedule(block: bytes) -> list:
    """
    Expande um bloco de 512 bits (64 bytes) em 64 palavras de 32 bits.

    As primeiras 16 palavras vêm direto do bloco.
    As 48 restantes são derivadas das anteriores com gamma0 e gamma1.
    """
    # Divide o bloco em 16 palavras de 32 bits
    w = list(struct.unpack('>16I', block))

    # Expande de 16 para 64 palavras
    for i in range(16, 64):
        w.append(
            (gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF
        )

    return w


# ============================================================
# ETAPA 3: COMPRESSÃO
# ============================================================

def compress(state: list, w: list) -> list:
    """
    Aplica 64 rodadas de compressão em um bloco.

    Mistura o estado atual (8 variáveis de 32 bits) com as
    64 palavras do schedule, usando as constantes K.
    """
    a, b, c, d, e, f, g, h = state

    for i in range(64):
        # Duas funções de mistura principais
        t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xFFFFFFFF
        t2 = (sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF

        # Rotaciona as variáveis
        h = g
        g = f
        f = e
        e = (d + t1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (t1 + t2) & 0xFFFFFFFF

    # Soma o estado comprimido ao estado inicial do bloco (Davies–Meyer)
    return [
        (x + y) & 0xFFFFFFFF
        for x, y in zip([a, b, c, d, e, f, g, h], state)
    ]


# ============================================================
# FUNÇÃO PRINCIPAL: SHA-256
# ============================================================

def sha256(message: bytes) -> str:
    """
    Calcula o SHA-256 de uma mensagem em bytes.
    Retorna o hash como string hexadecimal de 64 caracteres.
    """
    # 1. Padding
    padded = pad_message(message)

    # 2. Estado inicial (H0–H7)
    state = H_INIT[:]

    # 3. Processa cada bloco de 512 bits
    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        w = message_schedule(block)     # expande o bloco
        state = compress(state, w)      # comprime o bloco

    # 4. Produz o digest final (concatena H0–H7 em hexadecimal)
    return ''.join(f'{h:08x}' for h in state)


# ============================================================
# TESTES
# ============================================================

if __name__ == '__main__':
    texto = input("Digite o texto: ")
    print(sha256(texto.encode('utf-8')))