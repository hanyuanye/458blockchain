import hashlib
import random

p = 168199388701209853920129085113302407023173962717160229197318545484823101018386724351964316301278642143567435810448472465887143222934545154943005714265124445244247988777471773193847131514083030740407543233616696550197643519458134465700691569680905568000063025830089599260400096259430726498683087138415465107499

q = 959452661475451209325433595634941112150003865821

g = 94389192776327398589845326980349814526433869093412782345430946059206568804005181600855825906142967271872548375877738949875812540433223444968461350789461385043775029963900638123183435133537262152973355498432995364505138912569755859623649866375135353179362670798771770711847430626954864269888988371113567502852

pk1 = 49336018324808093534733548840411752485726058527829630668967480568854756416567496216294919051910148686186622706869702321664465094703247368646506821015290302480990450130280616929226917246255147063292301724297680683401258636182185599124131170077548450754294083728885075516985144944984920010138492897272069257160

sk1 = 432398415306986194693973996870836079581453988813
sk2 = 165849943586922055423650237226339279137759546603
sk3 = 627658512551971075308886219669315148725310346887

amnt0 = 1
amnt1 = 2
amnt2 = 3
amnt3 = 4


def exponent(g, x, n):
    bitfield = [1 if digit == '1' else 0 for digit in bin(x)[2:]]
    val = 1
    for bit in bitfield:
        val = val ** 2 % n
        if bit == 1:
            val = val * g % n

    return val


def sha3224(n):
    hash = hashlib.sha3_224()
    hexMessage = hex(n)[2:]
    bytearray = bytes(hexMessage, encoding='utf-8')
    hash.update(bytearray)
    binary_string = "{0:020b}".format(int(hash.hexdigest(), 16))
    return binary_string


def setup(p, g, sk):
    return exponent(g, sk, p)


def generate_message(pk1, pk2, amnt):
    # return pk1  pk2 | amnt
    bitfield1 = [1 if digit == '1' else 0 for digit in bin(pk1)[2:]][:399]
    bitfield2 = [1 if digit == '1' else 0 for digit in bin(pk2)[2:]][:399]
    bitfield3 = [1 if digit == '1' else 0 for digit in bin(amnt)[2:]]
    bitfield = bitfield1
    bitfield.extend(bitfield2)
    bitfield.extend(bitfield3)

    i = 0
    for bit in bitfield:
        i = (i << 1) | bit
    return i


def generate_signature(m, p, q, g, sk):
    while True:
        k = random.randrange(q) + 1
        r = exponent(g, k, p)
        h = int(sha3224(m))
        factor = h - r * sk
        inv_mod = pow(k, -1, q)
        s = factor * inv_mod % q
        if s != 0:
            return r, s


def verify_signature(m, r, s, g, p, q, pk):
    valid = 0 < r < p and 0 < s < p
    if not valid:
        return False
    s_inv = pow(s, -1, q)
    h = int(sha3224(m))
    u = h * s_inv % q
    v = -r * s_inv % q
    w = exponent(g, u, p) * exponent(pk, v, p) % p
    print(r)
    print(w)
    return w == r


def find_nonce(n, idx):
    start = 0
    count = 0
    while True:
        x = sha3224(start)
        correct = 224 - len(x) >= n

        if correct:
            count += 1
            if count >= idx:
                return start

        start += 1


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    pk2 = exponent(g, sk2, p)
    pk3 = exponent(g, sk3, p)
    m1 = generate_message(pk1, pk2, amnt1)
    m2 = generate_message(pk2, pk3, amnt2)
    r, s = generate_signature(m1, p, q, g, sk1)
    verified = verify_signature(m1, r, s, g, p, q, pk1)
    print(verified)

    nonce1 = find_nonce(24, 1)
    print(sha3224(nonce1))
    print(len(sha3224(nonce1)))
    print(nonce1)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
