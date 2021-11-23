from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.hash_module import Hash, int2Bytes
from charm.core.math.integer import randomBits, bitsize, integer


class BasicIdent:
    def __init__(self):
        # Random generator P in G1
        self.group = PairingGroup('SS512', secparam=1024)
        self.P = self.group.random(G1)
        # Random s in Z_q^*
        self.s = self.group.random(ZR)

        self.P_pub = self.s * self.P

        # Assume these are cryptographic
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
        Q_id = self.group.hash(ID, G1)
        # r is random in Z_q^*
        r = self.group.random(ZR)
        # P_pub = P*s
        g_id = pair(Q_id, self.P_pub)
        C = {"U": r * self.P, "V": M ^ self.h.hashToZn(g_id ** r)}
        return C

    def decrypt(self, C, d_id):
        # ê(d_id, U)
        e = pair(d_id, C['U'])
        hashed_e = self.h.hashToZn(e)
        decrypted = C['V'] ^ hashed_e
        M = int2Bytes(decrypted)
        M = M.decode('utf-8')
        return M


bIdent = BasicIdent()
# Per extracts his private key
private_key = bIdent.extract("Per@AU")
# Someone encryptes a message for Per
C = bIdent.encrypt("Per you are nice", "Per@AU")
# Per decrypts message
M = bIdent.decrypt(C, private_key)
print(M)
