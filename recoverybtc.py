import ecdsa
import os
import base58

hash_of_transaction = b"1390bd702894c4f0fa804cc2eeee3a033085f538c4e238eb91c1ef7caf8a2491" # example transaction hash, should be in bytes
public_key_base58 = "3ACquHUrjAkTDgBKbKWyWdHyZabqYVkKk9" # example base58 encoded public key

# Create an instance of the VerifyingKey class using the provided public key
curve = ecdsa.SECP256k1
public_key_bytes = base58.b58decode(public_key_base58)
print(public_key_bytes)
public_key = ecdsa.VerifyingKey.from_string(public_key_bytes, curve=curve)

# Generate a 32-byte random number using os.urandom()
random_number = int.from_bytes(os.urandom(32), byteorder='big')

curve_order = curve.order

def modinv(a, m):
    # Calculate the extended Euclidean algorithm
    gcd, x, y = extended_gcd(a, m)

    # If the gcd isn't 1, then the modular inverse doesn't exist
    if gcd != 1:
        raise ValueError('Modular inverse does not exist')

    # Return the modular inverse of a modulo m
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

modinv_random_number = modinv(random_number, curve.order)

# Use the recover_from_hash() method to get the public key point from the hash of the transaction
public_key_point = public_key.pubkey.recover_from_hash(hash_of_transaction, signature=None)

# Calculate the private key
private_key = ((int.from_bytes(hash_of_transaction, 'big') * public_key_point.x()) * pow(random_number, curve_order - 2, curve_order)) % curve_order

# Output the result
print(hex(private_key))
