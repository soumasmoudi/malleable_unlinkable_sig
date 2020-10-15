""" An implementation of the unlinkable malleable signature based on the Pointcheval-Sanders Signature
scheme, to demonnstrate the usability of the IMS construction.
"""


from bplib.bp import BpGroup
from petlib.bn import Bn
from hashlib import sha256


# -----------generate the group parameters--------------#
def group_params():
    cg = BpGroup()
    g1, g2 = cg.gen1(), cg.gen2()
    e, o = cg.pair, cg.order()
    return cg, o, g1, g2, e


# -----------generate the pair of keys of the signer--------------#
def sig_keygen(params):
    (G, o, g1, g2, e) = params
    (x, y) = o.random(), o.random()
    sk = (x, y)
    pk = (g2, x * g2, y * g2)
    return sk, pk


# -----------generate the weights associated to the different types of attributes --------------#
def weight_gen(params, sk, types_nbr):   # types_nbr represents the number of attributes' types
    (G, o, g1, g2, e) = params
    (x, y) = sk
    v = []
    w = []
    for i in range(types_nbr):
        v.append(o.random())
        w.append(o.random())
    p = []
    q = []
    for j in range(types_nbr):
        p.append((v[j] * y) * g2)
        q.append(w[j] * g2)
    return v, w, p, q


# -----------generate the pair of keys of the sanitizer--------------#
def user_keygen(params, sk, pk):
    (G, o, g1, g2, e) = params
    (x, y) = sk
    (g, X, Y) = pk
    (alpha, beta) = o.random(), o.random()
    (xu, yu) = x * alpha, y * beta
    sku = (xu, yu)
    pku = (xu * g, yu * g)
    return alpha, beta, sku, pku


# -----------generate the signature--------------#
def sign(params, sk, sku, a, b, m, v, w, adm):  # adm contains the the indexes of admissible blocks (the indexes start from 1)
    (G, o, g1, g2, e) = params
    (x, y) = sk
    (xu, yu) = sku
    h = (o.random()) * g1
    mes = []
    for i in range(len(m)):
        mes.append(Bn.from_binary(sha256(m[i].encode('utf-8')).digest()))
    c1 = 0
    c2 = 0
    for i in range(len(m)):
        c1 = c1 + (v[i] * mes[i] * y) + (mes[i] * y) + w[i]
        c2 = c2 + (mes[i] * yu)
    res1 = x + c1
    res2 = xu + c2
    su = o.random()
    au = su * h
    bu = res1 * h
    cu = res2 * h
    sigma = (su, au, bu, cu)
    hu = []
    for i in adm:
        hj = (v[i - 1] * mes[i - 1] * y) + w[i - 1]
        hu.append(hj * h)
    sig1 = a * g1
    sig2 = b * g1
    sig3 = y * h
    return h, sigma, sig1, sig2, sig3, hu


# -----------modify the message and accordingly the signature--------------#
def modify(params, m, sigma, sku, pku, MOD, ADM): # MOD is a subset of ADM
    (G, o, g1, g2, e) = params
    (Xu, Yu) = pku
    (xu, yu) = sku
    (h, sig) = sigma
    (sig1, sig2, sig3, H) = ADM
    su, au, bu, cu = sign
    (rsp, rho, t, z) = o.random(), o.random(), o.random(), o.random()
    rho_inv = rho.mod_inverse(o)
    mod_m = m.copy()
    for i in MOD:
        mod_m.remove(m[i-1])
    mes = []
    for i in range(len(m)):
        mes.append(Bn.from_binary(sha256(m[i].encode('utf-8')).digest()))
    su1 = su * rsp
    au1 = rsp * au
    for j in MOD:
        bu = bu - (H[j - 1]) - ((mes[j - 1]) * sig3)
        cu = cu - ((yu * mes[j - 1]) * h)
    bu1 = bu
    cu1 = cu
    xu1 = rho * xu
    yu1 = rho * yu
    sku1 = (xu1, yu1)
    Xu1 = rho * Xu
    Yu1 = rho * Yu
    pku1 = (Xu1, Yu1)
    elem1 = z * sig1
    elem2 = z * sig2
    elem3 = (z * rho_inv) * g1
    au2 = t * au1
    bu2 = t * bu1
    cu2 = (rho * t) * cu1
    du2 = bu2 + cu2
    mod_sigma = (su1, au2, du2)
    return mod_m, mod_sigma, sku1, pku1, elem1, elem2, elem3, z, rho


# -----------verify the validity of the signature--------------#
def verify(params, m, sigma, pk, pku, p, q, el1, el2, el3):
    (G, o, g1, g2, e) = params
    (g, X, Y) = pk
    (Xu, Yu) = pku
    (s, a, d) = sigma
    mes = []
    for i in range(len(m)):
        mes.append(Bn.from_binary(sha256(m[i].encode('utf-8')).digest()))
    a1 = ((p[0] + Y + Yu) * mes[0]) + q[0]
    for i in range(len(m)):
        if i != 0:
            a1 = a1 + ((p[i] + Y + Yu) * mes[i]) + q[i]
    return e(a, Xu + X + a1) == e(d, g) ** s and e(el3, Xu) == e(el1, X) and e(el3, Yu) == e(el2, Y)


