import random

def diffie_hellman():
    # Step 1: Agree on public values
    p = 23 # Prime number
    g = 5  # Primitive root modulo p
    # print(f"Publicly agreed values:\np={p}, g={g}\n")
    print("p=", p, " g=", g)

    # Step 2: Private keys chosen by Alice and Bob
    a = random.randint(1, p-2)
    b = random.randint(1, p-2)
    print(f"Alice's private key (a): {a}")
    print(f"Bob's private key (b): {b}\n")

    # Step 3: Compute public keys
    A = pow(g, a, p)
    B = pow(g, b, p)
    print(f"Alice's public key (A): {A}")
    print(f"Bob's public key (B): {B}\n")

    # Step 4: Compute shared secrets
    shared_secret_alice = pow(B, a, p)  
    shared_secret_bob = pow(A, b, p)
    print(f"Alice computes shared secret: {shared_secret_alice}")
    print(f"Bob computes shared secret: {shared_secret_bob}\n")

    # Verify that both shared secrets are equal
    if shared_secret_alice == shared_secret_bob:
        print("Success! Both shared secrets match.")
    else:
        print("Error! Shared secrets do not match.")

# Run the program
diffie_hellman()