#GCD where a is the larger number
def gcd(a, b):
    if b == 0:
        return a
    else:
        a %= b
    return gcd(b, a)

print(gcd(978, 89798763754892653453379597352537489494736))