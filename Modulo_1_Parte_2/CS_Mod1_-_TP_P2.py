# ==============================================================================
#   Instituto Superior de Engenharia de Lisboa - 2026/27 - Semestre de Inverno
#   Disciplina: Cibersegurança
#
#   Trabalho Prático - Módulo 1 - Parte 2
#   Sistema de cifra de Regev baseado no problema LWE (Learning With Errors)
#
#   Alunos:
#   + 49448 - Rodrigo Dos Ramos Pais Henriques Vitorino
#   + 51745 - Jessé Ferreira de Moura Alencar
# ==============================================================================
import numpy as np

# ========================== IMPLEMENTAÇÕES ====================================

def cifra_Regev(n, m, beta, q, chave_publica, mu, r=None) -> tuple:
    """
    Cifra UM bit mu com o sistema de cifra de Regev (LWE).

    Parâmetros:
    - n, m, beta, q: parâmetros do esquema (A é n x m, ruído/efémeras em [-beta, beta]).
    - chave_publica: par (A, b) com A de tipo n x m e b vetor com n entradas, em Zq.
    - mu: bit a cifrar, 0 ou 1.
    - r: (OPCIONAL) vetor efémero a usar, com n entradas em [-beta, beta]. Se for None
         (comportamento normal do esquema), é gerado um vetor aleatório novo. Serve
         para reproduzir uma cifra concreta, por exemplo a de um exemplo do enunciado.

    Retorno:
    - (u, nu, r):
        u  -> vetor com m entradas, u^T = r^T A mod q
        nu -> inteiro, nu = (r^T b + floor(q/2)*mu) mod q
        r  -> vetor efémero usado na cifragem
              (devolvido apenas para permitir verificações/testes a posteriori)
    """
    A, b = chave_publica
    A = np.array(A, dtype=object)   # dtype=object evita overflow em inteiros grandes
    b = np.array(b, dtype=object).reshape(-1)

    # Verificação de coerência da chave pública com os parâmetros n e m
    if A.shape != (n, m):
        raise ValueError(f"Matriz A com dimensao {A.shape}, esperado ({n}, {m})")
    if b.shape[0] != n:
        raise ValueError(f"Vetor b com {b.shape[0]} entradas, esperado {n}")
    if mu not in (0, 1):
        raise ValueError(f"mu deve ser 0 ou 1, recebido {mu}")

    # Vetor efémero r: n entradas em [beta] = {-beta, ..., 0, ..., beta}
    if r is None:
        # Caso normal: gera-se um vetor aleatório novo em cada cifragem
        r = np.array([int(x) for x in np.random.randint(-beta, beta + 1, size=n)], dtype=object)
    else:
        # Caso de teste: usa-se o vetor fornecido, validando dimensao e intervalo
        r = np.array(r, dtype=object).reshape(-1)
        if r.shape[0] != n:
            raise ValueError(f"Vetor r com {r.shape[0]} entradas, esperado {n}")
        if any(abs(int(x)) > beta for x in r):
            raise ValueError(f"Vetor r com entradas fora de [-{beta}, {beta}]")

    # u^T = r^T A mod q          (produto matricial usual: @, nunca *)
    u = (r @ A) % q

    # nu = (r^T b + floor(q/2) * mu) mod q
    nu = int((int(r @ b) + (q // 2) * mu) % q)

    return u, nu, r


def decifra_Regev(q, secreto, cifra) -> int:
    """
    Decifra um par (u, nu) produzido pela cifra de Regev.

    Parâmetros:
    - q: módulo do esquema.
    - secreto: vetor privado s com m entradas.
    - cifra: par (u, nu).

    Retorno:
    - mu: bit decifrado, 0 ou 1.
      Regra: se q/4 < (nu - u^T s) mod q < 3q/4 então mu = 1, caso contrário mu = 0.
    """
    u, nu = cifra
    u = np.array(u, dtype=object).reshape(-1)
    s = np.array(secreto, dtype=object).reshape(-1)

    if u.shape[0] != s.shape[0]:
        raise ValueError(f"Dimensoes incompativeis: u tem {u.shape[0]}, s tem {s.shape[0]}")

    # d = (nu - u^T s) mod q
    d = (int(nu) - int(u @ s)) % q

    return 1 if q / 4 < d < 3 * q / 4 else 0

# ==============================================================================
#   Funções auxiliares
# ==============================================================================

def gera_chaves_Regev(n, m, beta, q) -> tuple:
    """
    Geração de chaves do esquema de Regev.

    - s: vetor secreto não nulo, m entradas em Zq.
    - e: vetor de ruído não nulo, n entradas em [-beta, beta].
    - A: matriz n x m com entradas em Zq.
    - b = (A s + e) mod q.

    Retorno: ((A, b), s, e)  ->  chave pública, chave privada e ruído usado.
    """
    # s não nulo, entradas em Zq
    while True:
        s = np.array([int(x) for x in np.random.randint(0, q, size=m)], dtype=object)
        if np.any(s != 0):
            break

    # e não nulo, entradas em [beta]
    while True:
        e = np.array([int(x) for x in np.random.randint(-beta, beta + 1, size=n)], dtype=object)
        if np.any(e != 0):
            break

    A = np.array([[int(x) for x in linha] for linha in np.random.randint(0, q, size=(n, m))], dtype=object)
    b = (A @ s + e) % q

    return (A, b), s, e


def calcular_B(A, s, e, q):
    """
    Calcula o vetor b da chave pública a partir de A, do secreto s e do ruído e:
        b = (A s + e) mod q

    Parâmetros:
    - A: matriz n x m com entradas em Zq.
    - s: vetor secreto com m entradas.
    - e: vetor de ruído com n entradas em [-beta, beta].
    - q: módulo do esquema.

    Retorno:
    - b: vetor com n entradas em Zq.

    Útil quando o enunciado fornece A, s e e em vez de b, ou para confirmar que um
    b dado é coerente com os restantes dados.
    """
    A = np.array(A, dtype=object)
    s = np.array(s, dtype=object).reshape(-1)
    e = np.array(e, dtype=object).reshape(-1)

    if A.shape[1] != s.shape[0]:
        raise ValueError(f"Dimensoes incompativeis: A tem {A.shape[1]} colunas, s tem {s.shape[0]}")
    if A.shape[0] != e.shape[0]:
        raise ValueError(f"Dimensoes incompativeis: A tem {A.shape[0]} linhas, e tem {e.shape[0]}")

    return (A @ s + e) % q


def valor_decifrado(q, secreto, cifra) -> int:
    """
    Devolve o valor intermédio d = (nu - u^T s) mod q usado no decifrado.
    Útil para mostrar a margem de decisão face aos limiares q/4 e 3q/4.
    """
    u, nu = cifra
    u = np.array(u, dtype=object).reshape(-1)
    s = np.array(secreto, dtype=object).reshape(-1)
    return (int(nu) - int(u @ s)) % q


def condicao_decifrado_correto(n, beta, q) -> bool:
    """
    Verifica a condição suficiente de decifrado sempre correto: 4*n*beta^2 < q - 1.
    """
    return 4 * n * beta ** 2 < q - 1


def formata_vetor(v) -> str:
    """Formata um vetor numpy numa linha legível, ex.: [97, 160, 210]."""
    return "[" + ", ".join(str(int(x)) for x in np.array(v).reshape(-1)) + "]"


def imprimir_matriz(nome, M) -> None:
    """Imprime uma matriz linha a linha, alinhada, com o nome como prefixo."""
    M = np.array(M)
    largura = max(len(str(int(x))) for x in M.reshape(-1))
    prefixo = f"{nome} = "
    espacos = " " * len(prefixo)
    for i, linha in enumerate(M):
        celulas = "  ".join(str(int(x)).rjust(largura) for x in linha)
        print(f"{prefixo if i == 0 else espacos}[ {celulas} ]")

# ==============================================================================

def imprimir_separador():
    print("=" * 60)


def imprimir_titulo():
    imprimir_separador()
    print("Instituto Superior de Engenharia de Lisboa - 2026/27 - Semestre de Inverno")
    print("Disciplina: Ciberseguranca")
    print("Trabalho Pratico - Modulo 1 - Parte 2")
    print("Sistema de cifra de Regev baseado no LWE")
    print("Alunos:")
    print("+ 49448 - Rodrigo Dos Ramos Pais Henriques Vitorino")
    print("+ 51745 - Jesse Ferreira de Moura Alencar")
    imprimir_separador()

# ==============================================================================

def executar_exercicio_1():
    print("RESOLUCAO - EXERCICIO 1")
    imprimir_separador()

    # Parâmetros fornecidos
    n = 5
    m = 3
    q = 307
    beta = 3

    # Vetor efemero r: OPCIONAL. Se for None, é gerado aleatoriamente na cifragem.
    # Preencher apenas para reproduzir uma cifra concreta, p.ex. [1, -2, -2, 0, 0].
    r_fornecido = [1, -2, -2, 0, 0] # None

    print(f"Parametros fornecidos: n = {n}, m = {m}, q = {q}, beta = {beta}")

    # Chave publica de Bob (A, b)
    A = np.array([
        [ 45, 211, 291],
        [265, 241, 163],
        [ 16, 245,  31],
        [278, 257, 238],
        [ 70, 224, 247],
    ], dtype=object)

    b = np.array([75, 247, 262, 109, 191], dtype=object)
    # Em alternativa, se o enunciado fornecer s e e em vez de b:
    # b = calcular_B(A, s_Bob, e_Bob, q)

    print("Chave publica de Bob K_pub_B = (A, b):")
    imprimir_matriz("A", A)
    print(f"b = {formata_vetor(b)}\n")

    chave_publica_Bob = (A, b)

    # --- Questao 1: Alice cifra o bit mu = 1 com a chave publica de Bob ---
    print("- Questao 1: Alice cifra mu = 1 com a chave publica de Bob")

    mu_Alice = 1
    u_Alice, nu_Alice, r_Alice = cifra_Regev(n, m, beta, q, chave_publica_Bob, mu_Alice, r_fornecido)

    origem_r = "fornecido" if r_fornecido is not None else "gerado"
    print(f"  + Vetor efemero r {origem_r} por Alice: {formata_vetor(r_Alice)}")
    print(f"  + u^T = r^T A mod q: {formata_vetor(u_Alice)}")
    print(f"  + nu = (r^T b + floor(q/2)*mu) mod q: {nu_Alice}   (floor(q/2) = {q // 2})")
    print(f"  + Cifra de Alice (u, nu): ({formata_vetor(u_Alice)}, {nu_Alice})")

    # --- Questao 2: Bob decifra o texto cifrado enviado por Ana ---
    print("- Questao 2: Bob decifra o texto cifrado enviado por Ana")

    u_Ana = np.array([109, 145, 244], dtype=object)
    nu_Ana = 82
    s_Bob = np.array([1, 0, -2], dtype=object)   # chave privada de Bob

    print(f"  + Cifra recebida de Ana (u, nu): ({formata_vetor(u_Ana)}, {nu_Ana})")
    print(f"  + Chave privada de Bob s: {formata_vetor(s_Bob)}")

    d_Ana = valor_decifrado(q, s_Bob, (u_Ana, nu_Ana))
    mu_Ana = decifra_Regev(q, s_Bob, (u_Ana, nu_Ana))

    print(f"  + (nu - u^T s) mod q = {d_Ana}")
    print(f"  + Limiares de decisao: q/4 = {q / 4} e 3q/4 = {3 * q / 4}")
    print(f"  + Mensagem enviada por Ana: mu = {mu_Ana}\n")

    # --- Verificacao adicional: Bob decifra tambem a cifra de Alice ---
    print("- Verificacao: Bob decifra a cifra produzida por Alice")

    d_Alice = valor_decifrado(q, s_Bob, (u_Alice, nu_Alice))
    mu_recuperado = decifra_Regev(q, s_Bob, (u_Alice, nu_Alice))

    print(f"  + (nu - u^T s) mod q = {d_Alice}")
    print(f"  + Bit decifrado: mu = {mu_recuperado} (enviado: {mu_Alice})")
    print(f"  + Decifrado correto: {mu_recuperado == mu_Alice}")
    imprimir_separador()

# ==============================================================================

def executar_exercicio_2():
    print("RESOLUCAO - EXERCICIO 2")
    imprimir_separador()

    # Parametros fornecidos 
    n = 5
    m = 3
    q = 307
    beta = 3

    print(f"Parametros fornecidos: n = {n}, m = {m}, q = {q}, beta = {beta}")
    ok = condicao_decifrado_correto(n, beta, q)
    print(f"Condicao 4*n*beta^2 < q-1: 4*{n}*{beta}^2 = {4 * n * beta ** 2} < {q - 1} -> {ok}\n")

    if not ok:
        print("  + PROBLEMA: parametros nao garantem decifrado sempre correto.\n")

    A = np.array([
        [ 45, 211, 291],
        [265, 241, 163],
        [ 16, 245,  31],
        [278, 257, 238],
        [ 70, 224, 247],
    ], dtype=object)

    b = np.array([75, 247, 262, 109, 191], dtype=object)

    print("Chave publica de Bob K_pub_B = (A, b):")
    imprimir_matriz("A", A)
    print(f"b = {formata_vetor(b)}\n")

    chave_publica_Bob = (A, b)
    s_Bob = np.array([1, 0, -2], dtype=object)

    # --- Cifra de Alice ---
    print("- Alice cifra mu = 1 com a chave publica de Bob")

    mu_Alice = 1
    u_Alice, nu_Alice, r_Alice = cifra_Regev(n, m, beta, q, chave_publica_Bob, mu_Alice)

    print(f"  + Vetor efemero r gerado por Alice: {formata_vetor(r_Alice)}")
    print(f"  + Cifra de Alice (u, nu): ({formata_vetor(u_Alice)}, {nu_Alice})\n")

    # Emular corrupcao da cifra em transito (um dado com problema)
    u_corrompido = u_Alice.copy()
    u_corrompido[0] = (int(u_corrompido[0]) + 97) % q
    print(f"- Cifra alterada em transito (u corrompido): ({formata_vetor(u_corrompido)}, {nu_Alice})\n")

    # --- Bob decifra a cifra corrompida ---
    print("- Bob decifra a cifra recebida")
    print(f"  + Chave privada de Bob s: {formata_vetor(s_Bob)}")

    d = valor_decifrado(q, s_Bob, (u_corrompido, nu_Alice))
    mu_recuperado = decifra_Regev(q, s_Bob, (u_corrompido, nu_Alice))

    print(f"  + (nu - u^T s) mod q = {d}")
    print(f"  + Limiares de decisao: q/4 = {q / 4} e 3q/4 = {3 * q / 4}")
    print(f"  + Bit decifrado: mu = {mu_recuperado} (enviado: {mu_Alice})")

    if mu_recuperado != mu_Alice:
        print("  + PROBLEMA: o bit decifrado nao coincide com o bit enviado.")
        print("    A cifra (u, nu) foi alterada, logo (nu - u^T s) mod q caiu do lado errado")
        print("    do limiar de decisao. O esquema de Regev nao tem integridade: nada")
        print("    permite a Bob detetar a alteracao, apenas obtem um bit errado.")
    else:
        print("  + Sem problema detetado neste decifrado.")

    imprimir_separador()

# ==============================================================================

def executar_testes():
    """
    Teste de sanidade: gera um par de chaves, cifra e decifra vários bits
    e confirma que o bit recuperado coincide com o bit original.
    """
    print("TESTES DE SANIDADE (geracao de chaves + cifra + decifra)")
    imprimir_separador()

    n, m, beta, q = 20, 5, 2, 4099

    print(f"Parametros: n = {n}, m = {m}, beta = {beta}, q = {q}")

    chave_publica, s, e = gera_chaves_Regev(n, m, beta, q)

    print(f"Chave privada gerada s: {formata_vetor(s)}")
    print(f"Ruido gerado e: {formata_vetor(e)}\n")

    num_testes = 100
    sucessos = 0
    for i in range(num_testes):
        mu = i % 2
        u, nu, _ = cifra_Regev(n, m, beta, q, chave_publica, mu)
        if decifra_Regev(q, s, (u, nu)) == mu:
            sucessos += 1

    print(f"Bits cifrados e decifrados corretamente: {sucessos}/{num_testes}")
    imprimir_separador()

# ==============================================================================

if __name__ == "__main__":
    imprimir_titulo()
    executar_exercicio_1()
    executar_exercicio_2()
    # executar_testes()
