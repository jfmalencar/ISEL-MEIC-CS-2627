# ==============================================================================
#   Instituto Superior de Engenharia de Lisboa - 2026/27 - Semestre de Inverno
#   Disciplina: Cibersegurança
#   
#   Trabalho Prático - Módulo 1 - Parte 1
#   Alunos:
#   + 49448 - Rodrigo Dos Ramos Pais Henriques Vitorino
#   + 51745 - Jessé Ferreira de Moura Alencar
# ==============================================================================
import random

# ========================== IMPLEMENTAÇÕES ====================================

def assina_RSA(chave_privada, lista_inteiros) -> int:
    """
    Assina uma lista de inteiros utilizando o esquema de assinatura RSA simples.
    
    Parâmetros:
    - chave_privada: Tuplo (n, d) com o módulo n e o expoente privado d.
    - lista_inteiros: Lista de inteiros (m1, ..., mk) a assinar.
    
    Retorno:
    - sign: Inteiro correspondente à assinatura RSA da soma da lista módulo n.
    """
    n, d = chave_privada
    m_soma = sum(lista_inteiros)
    m = m_soma % n
    sign = pow(m, d, n)
    return sign

def verifica_RSA(chave_publica, sign, lista_inteiros) -> bool:
    """
    Verifica se uma assinatura RSA é válida para uma lista de inteiros.
    
    Parâmetros:
    - chave_publica: Tuplo (n, e) com o módulo n e o expoente público e.
    - sign: Inteiro a validar como assinatura.
    - lista_inteiros: Lista de inteiros (m1, ..., mk).
    
    Retorno:
    - bool: True se a assinatura for válida, False caso contrário.
    """
    n, e = chave_publica
    m_soma = sum(lista_inteiros)
    m = m_soma % n
    m_recuperado = pow(sign, e, n)
    return m_recuperado == m

def chave_DH(p, alpha) -> tuple:
    """
    Gera um par de chaves (privada, pública) Diffie-Hellman.
    
    Parâmetros:
    - p: Número primo (módulo do domínio DH).
    - alpha: Gerador multiplicativo módulo p.
    
    Retorno:
    - (x, beta): Tuplo com a chave privada x (1 < x < p-1) e pública beta (alpha^x mod p).
    """
    x = random.randint(2, p - 2)
    beta = pow(alpha, x, p)
    return x, beta

# ==============================================================================

def calcula_expoente_privado(chave_publica) -> int:
    """
    Fatoriza n em primos p e q e calcula d = e^(-1) mod phi(n).
    Utilizado para determinar IK_pri a partir de IK_pub nos testes.
    """
    # Encontrar fatores primos p e q
    n, e = chave_publica
    p, q = None, None
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            p = i
            q = n // i
            break
    if p is None:
        raise ValueError(f"Não foi possível fatorizar {n}")
    
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    return d

def calcula_chave_partilhada_DH(p, chave_privada_propria, chave_publica_outro) -> int:
    """
    Calcula o segredo partilhado Diffie-Hellman K = (beta_outro)^x mod p.
    """
    return pow(chave_publica_outro, chave_privada_propria, p)

# ==============================================================================

def imprimir_separador():
    print("=" * 60)

def imprimir_titulo():
    imprimir_separador()
    print("Instituto Superior de Engenharia de Lisboa - 2026/27 - Semestre de Inverno")
    print("Disciplina: Ciberseguranca")
    print("Trabalho Pratico - Modulo 1 - Parte 1")
    print("Alunos:")
    print("+ 49448 - Rodrigo Dos Ramos Pais Henriques Vitorino")
    print("+ 51745 - Jesse Ferreira de Moura Alencar")
    imprimir_separador()


def executar_exercicio_1():
    print("RESOLUCAO - EXERCICIO 1")
    imprimir_separador()

    # Parâmetros fornecidos
    p = 233
    alpha = 95

    print(f"Parametros fornecidos: p = {p}, alpha = {alpha}\n")

    # Chaves públicas RSA de identidade
    pub_key_Alice = (551, 191)  # Alice (nA, eA)
    pub_key_Bob = (527, 193)    # Bob (nB, eB)

    print(f"Chave Publica de Alice IK_pub_A: {pub_key_Alice}")
    print(f"Chave Publica de Bob   IK_pub_B: {pub_key_Bob}\n")
    
    # Cálculo das chaves privadas RSA de identidade
    dA = 95     # calcula_expoente_privado(pub_key_Alice)
    dB = 97     # calcula_expoente_privado(pub_key_Bob)
    
    priv_key_Alice = (pub_key_Alice[0], dA)
    priv_key_Bob = (pub_key_Bob[0], dB)
    
    print(f"Chave Privada de Alice IK_pri_A: {priv_key_Alice}")
    print(f"Chave Privada de Bob   IK_pri_B: {priv_key_Bob}\n")
    
    # --- Passo 1: Chave efémera de Alice (xA = 5 para reprodutibilidade) ---
    x, beta = chave_DH(p, alpha)
    ef_priv_key_Alice = x
    ef_pub_key_Alice = beta

    print(f"- Alice - Chave efemera DH (EK_pub_A, EK_pri_A): ({ef_pub_key_Alice}, {ef_priv_key_Alice})\n")
    
    # --- Passo 2: Bob envia a Alice (EK_pub_B, sig_IK_B(...)) ---
    # x, beta = chave_DH(p, alpha)
    # ef_priv_key_Bob = x
    ef_pub_key_Bob = 149    # beta

    print(f"- Bob - Chave efemera publica DH (EK_pub_B): {ef_pub_key_Bob}\n")

    # Lista de inteiros: [nA, eA, nB, eB, EK_pub_A, EK_pub_B]
    list_Bob = [pub_key_Alice[0], pub_key_Alice[1], pub_key_Bob[0], pub_key_Bob[1], ef_pub_key_Alice, ef_pub_key_Bob]
    print(f"- Lista de inteiros a assinar por Bob: {list_Bob}")

    sig_B = assina_RSA(priv_key_Bob, list_Bob)
    print(f"- Assinatura de Bob sig_IK_B: {sig_B}")

    print(f"- Bob envia a Alice (EK_pub_B, sig_IK_B): ({ef_pub_key_Bob}, {sig_B})\n")

    print(f"- Lista de inteiros a verificar por Alice: {list_Bob}")
    validated_Bob = verifica_RSA(pub_key_Bob, sig_B, list_Bob)
    print(f"  + Verificacao da assinatura de Bob por Alice: {validated_Bob}" + validated_Bob * "\n" + (not validated_Bob) * "")

    if not validated_Bob:
        print("  + Assinatura de Bob invalida. Processo abortado.")
        imprimir_separador()
        return
    
    # --- Passo 3: Alice envia a Bob sig_IK_A(...) ---
    # Lista de inteiros: [eA, EK_pub_B]
    list_alice = [ef_pub_key_Alice, ef_pub_key_Bob]
    print(f"- Lista de inteiros a assinar por Alice: {list_alice}")

    sig_A = assina_RSA(priv_key_Alice, list_alice)
    print(f"- Assinatura de Alice sig_IK_A: {sig_A}")
    
    print(f"- Alice envia a Bob sig_IK_A: {sig_A}\n")

    print(f"- Lista de inteiros a verificar por Bob: {list_alice}")
    validated_Alice = verifica_RSA(pub_key_Alice, sig_A, list_alice)
    print(f"  + Verificacao da assinatura de Alice por Bob: {validated_Alice}" + validated_Alice * "\n" + (not validated_Alice) * "")

    if not validated_Alice:
        print("  + Assinatura de Alice invalida. Processo abortado.")
        imprimir_separador()
        return
    
    # --- Passo 4: Chave secreta partilhada Diffie-Hellman ---
    K = calcula_chave_partilhada_DH(p, ef_priv_key_Alice, ef_pub_key_Bob)
    print(f"- Chave secreta partilhada K = DH(EK_A, EK_B): {K}")
    imprimir_separador()

# ==============================================================================

def executar_exercicio_2():
    print("RESOLUCAO - EXERCICIO 2")
    imprimir_separador()

    # Parâmetros fornecidos
    p = 53
    alpha = 21

    print(f"Parametros fornecidos: p = {p}, alpha = {alpha}\n")

    pub_key_Alice = (247, 77)   # Alice (nA, eA)
    pub_key_Bob = (119, 23)     # Bob (nB, eB)

    print(f"Chave Publica de Alice IK_pub_A: {pub_key_Alice}")
    print(f"Chave Publica de Bob   IK_pub_B: {pub_key_Bob}\n")
        
    # Cálculo das chaves privadas RSA de identidade
    dA = 101  # calcula_expoente_privado(pub_key_Alice)
    dB = 71   # calcula_expoente_privado(pub_key_Bob)
    
    priv_key_Alice = (pub_key_Alice[0], dA)
    priv_key_Bob = (pub_key_Bob[0], dB)
    
    print(f"Chave Privada de Alice IK_pri_A: {priv_key_Alice}")
    print(f"Chave Privada de Bob   IK_pri_B: {priv_key_Bob}\n")
    
    # --- Passo 1: Chave efémera de Alice (xA = 5 para reprodutibilidade) ---
    # x, beta = chave_DH(p, alpha)
    ef_priv_key_Alice = 37
    ef_pub_key_Alice = pow(alpha, ef_priv_key_Alice, p)     # beta = alpha^x mod p

    print(f"- Alice - Chave efemera DH (EK_pub_A, EK_pri_A): ({ef_pub_key_Alice}, {ef_priv_key_Alice})\n")
    
    # --- Passo 2: Bob envia a Alice (EK_pub_B, sig_IK_B(...)) ---
    # x, beta = chave_DH(p, alpha)
    ef_pub_key_Bob = 149
    # ef_priv_key_Bob = pow(alpha, ef_pub_key_Bob, p)       # beta = alpha^x mod p

    print(f"- Bob - Chave efemera publica DH (EK_pub_B): {ef_pub_key_Bob}\n")

    # Emular comprometimento da chave efémera de Alice
    compromised_ef_pub_key_Alice = 9
    print(f"- Alice - Chave efemera comprometida DH (EK_pub_A): {compromised_ef_pub_key_Alice}\n")

    # Lista de inteiros: [nA, eA, nB, eB, EK_pub_A, EK_pub_B]
    compromised_list_Bob = [pub_key_Alice[0], pub_key_Alice[1], pub_key_Bob[0], pub_key_Bob[1], compromised_ef_pub_key_Alice, ef_pub_key_Bob]
    print(f"- Lista de inteiros a assinar por Bob: {compromised_list_Bob}")

    sig_B = assina_RSA(priv_key_Bob, compromised_list_Bob)
    print(f"- Assinatura de Bob sig_IK_B: {sig_B}")

    print(f"- Bob envia a Alice (EK_pub_B, sig_IK_B): ({ef_pub_key_Bob}, {sig_B})\n")

    list_Bob = [pub_key_Alice[0], pub_key_Alice[1], pub_key_Bob[0], pub_key_Bob[1], ef_pub_key_Alice, ef_pub_key_Bob]
    print(f"- Lista de inteiros a verificar por Alice: {list_Bob}")

    validated_Bob = verifica_RSA(pub_key_Bob, sig_B, list_Bob)
    print(f"  + Verificacao da assinatura de Bob por Alice: {validated_Bob}" + validated_Bob * "\n" + (not validated_Bob) * "")
    
    # --- Passo 3: Alice envia a Bob sig_IK_A(...) ---
    if not validated_Bob:
        print("  + Assinatura de Bob invalida. Processo abortado.")
        imprimir_separador()
        return

    # Lista de inteiros: [eA, EK_pub_B]
    list_alice = [ef_pub_key_Alice, ef_pub_key_Bob]
    print(f"- Lista de inteiros a assinar por Alice: {list_alice}")

    sig_A = assina_RSA(priv_key_Alice, list_alice)
    print(f"- Assinatura de Alice sig_IK_A: {sig_A}")

    print(f"- Alice envia a Bob sig_IK_A: {sig_A}\n")

    print(f"- Lista de inteiros a verificar por Bob: {list_alice}")
    validated_Alice = verifica_RSA(pub_key_Alice, sig_A, list_alice)
    print(f"  + Verificacao da assinatura de Alice por Bob: {validated_Alice}" + validated_Alice * "\n" + (not validated_Alice) * "")

    if not validated_Alice:
            print("  + Assinatura de Alice invalida. Processo abortado.")
            imprimir_separador()
            return
    
    # --- Passo 4: Chave secreta partilhada Diffie-Hellman ---
    K = calcula_chave_partilhada_DH(p, ef_priv_key_Alice, ef_pub_key_Bob)
    print(f"4. Chave secreta partilhada K = DH(EK_A, EK_B): {K}")
    print("=" * 60)

# ==============================================================================

if __name__ == "__main__":
    imprimir_titulo()
    executar_exercicio_1()
    executar_exercicio_2()
    