from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.hash_module import Hash, int2Bytes
from charm.core.math.integer import randomBits, bitsize, integer


class FullDennt:
    def __init__(self):
        # Random generator P in G1
        self.group = PairingGroup('SS512', secparam=1024)
        self.P = self.group.random(G1)
        # Random s in Z_q^*
        self.s = self.group.random(ZR)

        self.P_pub = self.s * self.P

        # Assume these are cryptographic
        # H4 = {1,0}^n -> {1,0}^n. Use h.hashToZn(thingToHash). This is same as H2??
        # H3 = {0,1}^n x {0,1}^n -> Z_q^*. Use h.hashToZr(first, second)
        # H2 = G2 -> {1,0}^n. Use h.hashToZn(thingToHash)
        # H1 = Some string -> G_1^*. Use group.hash(stringToHash, G1)
        self.h = Hash(self.group)

    def extract(self, ID):
        Q_id = self.group.hash(ID, G1)
        d_id = self.s * Q_id
        return d_id

    def encrypt(self, M, ID):
        if isinstance(M, str):
            M = str.encode(M)
        # Convert bytes to integer
        M = integer(M)

        # sigma is rnadom element in {1,0}^n
        sigma = integer(randomBits(self.group.secparam))
        Q_id = self.group.hash(ID, G1)
        # r = H3(sigma, M)
        r = self.h.hashToZr(sigma, M)
        # P_pub = P*s
        g_id = pair(Q_id, self.P_pub)
        # C = rp, sigma^h2(g_id^r), m^H4(sigma)
        C = {"U": r * self.P, "V": sigma ^ self.h.hashToZn(g_id ** r), "W": M ^ self.h.hashToZn(sigma)}
        return C

    def decrypt(self, C, d_id):
        assert self.group.ismember(C['U'])

        # V ^H2(e(d_id,U)) = sigma
        sigma = C['V'] ^ self.h.hashToZn(pair(d_id, C['U']))
        # M = W ^ H4(sigma)
        M = C['W'] ^ self.h.hashToZn(sigma)
        M = int2Bytes(M)
        # r = H3(sigma, M)
        r = self.h.hashToZr(sigma, M)
        assert C['U'] == r * self.P
        M = M.decode('utf-8')
        return M


bIdent = FullDennt()
# Per extracts his private key
private_key = bIdent.extract("Per@AU")
# Someone encryptes a message for Per
C = bIdent.encrypt("Per you are nice", "Per@AU")
# Per decrypts message
M = bIdent.decrypt(C, private_key)
print(M)
