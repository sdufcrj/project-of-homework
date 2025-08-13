from ecdsa import SigningKey, SECP256k1, ecdsa
from ecdsa.ecdsa import generator_secp256k1
import random

# 获取曲线参数
curve = SECP256k1
G = generator_secp256k1
N = G.order()

# 初始化公钥点
PK_x = 0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6
PK_y = 0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
PK = ecdsa.ellipticcurve.Point(curve.curve, PK_x, PK_y, N)


def verify(e, r, s):
    """验证签名"""
    # 计算 w = s^{-1} mod N
    w = pow(s, -1, N)

    # 计算 u1 = e·w mod N, u2 = r·w mod N
    u1 = (e * w) % N
    u2 = (r * w) % N

    # 计算点 R = u1·G + u2·PK
    R_point = u1 * G + u2 * PK

    # 验证 R 点的 x 坐标是否等于 r
    return R_point.x() == r


def forge_signature():
    """伪造 ECDSA 签名"""
    # 生成随机数 u 和 v
    while True:
        u = random.randint(1, N - 1)
        if pow(u, N - 2, N) != 0:  # 判断 u 是否与 N 互质
            break

    while True:
        v = random.randint(1, N - 1)
        if pow(v, N - 2, N) != 0:  # 判断 v 是否与 N 互质
            break

    # 计算伪造的 R 点：R = u·G + v·PK
    R_point = u * G + v * PK
    r = R_point.x()

    # 计算伪造的 s 值：s = r·v^{-1} mod N
    v_inv = pow(v, -1, N)
    s = (r * v_inv) % N

    # 计算伪造的消息：e = u·r·v^{-1} mod N
    e = (u * r * v_inv) % N

    print(f"伪造的签名: (r={hex(r)}, s={hex(s)})")

    # 验证伪造的签名
    if verify(e, r, s):
        print("验证成功!")
    else:
        print("验证失败!")


if __name__ == "__main__":
    forge_signature()
