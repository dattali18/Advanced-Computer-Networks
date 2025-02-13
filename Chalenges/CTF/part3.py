import requests
from sympy import mod_inverse

# this part of the ctf will be breaking the rsa encryption
# we are given the following values use build in library to break the encryption

# You have proven yourself worthy... so far :)

# /PrivateKey.jpg is on the CTF's server

# Exponent: 0x10001

# Modulus: 0x221d49b02a45b172de232b09b

# Tip: Breaking RSA

# Extra Tips:

# Replace the string "PrivateKey" with the private key...

# The private key should be written in HexDecimal, small letters, start with 0x

# "import egcd" will be very usefull once P,Q are found

EXPONENT = 0x10001
MODULUS = 0x221d49b02a45b172de232b09

PRIVET_KEY = None

from sympy import factorint

def break_rsa(e, n):
    # we need to find the private key
    # we need to find the p and q values
    # we can do this by factoring the n value
    factors = factorint(n)
    p = list(factors.keys())[0]
    q = list(factors.keys())[1]
    # now we can find the private key
    phi = (p-1)*(q-1)
    d = mod_inverse(e, phi)
    return d

PRIVET_KEY = break_rsa(EXPONENT, MODULUS)

print(hex(PRIVET_KEY)) # 0x
