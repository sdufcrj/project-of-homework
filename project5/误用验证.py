import secrets
from hashlib import sha256
from gmssl import sm3, func

# 椭圆曲线参数
ECC_PARAM_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
ECC_PARAM_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
MODULUS_P = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
ORDER_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
BASE_PT_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
BASE_PT_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
BASE_POINT = (BASE_PT_X, BASE_PT_Y)


def modular_inverse(value, modulus):
    mult_low, mult_high = 1, 0
    val_low, val_high = value % modulus, modulus
    while val_low > 1:
        ratio = val_high // val_low
        new_mult = mult_high - mult_low * ratio
        new_val = val_high - val_low * ratio
        mult_low, val_low, mult_high, val_high = new_mult, new_val, mult_low, val_low
    return mult_low % modulus


def ecc_point_addition(point1, point2):
    slope = ((point2[1] - point1[1]) * modular_inverse(point2[0] - point1[0], MODULUS_P)) % MODULUS_P
    result_x = (slope * slope - point1[0] - point2[0]) % MODULUS_P
    result_y = (slope * (point1[0] - result_x) - point1[1]) % MODULUS_P
    return (result_x, result_y)


def ecc_point_doubling(point):
    slope = ((3 * point[0] * point[0] + ECC_PARAM_A) * modular_inverse((2 * point[1]), MODULUS_P)) % MODULUS_P
    result_x = (slope * slope - 2 * point[0]) % MODULUS_P
    result_y = (slope * (point[0] - result_x) - point[1]) % MODULUS_P
    return (result_x, result_y)


def scalar_point_multiplication(scalar, base_point):
    if scalar == 0 or scalar >= ORDER_N:
        raise ValueError("Invalid scalar or private key")
    scalar_binary = bin(scalar)[2:]
    temp_point = base_point
    for bit in scalar_binary[1:]:
        temp_point = ecc_point_doubling(temp_point)
        if bit == "1":
            temp_point = ecc_point_addition(temp_point, base_point)
    return temp_point


def calculate_bit_length(data):
    if isinstance(data, int):
        bit_count = 0
        while data:
            bit_count += 1
            data >>= 1
        return bit_count
    elif isinstance(data, str):
        return len(data.encode()) * 8
    elif isinstance(data, bytes):
        return len(data) * 8
    return 0


def compute_identity_hash(user_id, pub_x, pub_y):
    components = [
        str(calculate_bit_length(user_id)),
        user_id,
        str(ECC_PARAM_A),
        str(ECC_PARAM_B),
        str(BASE_PT_X),
        str(BASE_PT_Y),
        str(pub_x),
        str(pub_y)
    ]
    concatenated = "".join(components)
    digest = sm3.sm3_hash(func.bytes_to_list(concatenated.encode()))
    return int(digest, 16)


def create_key_pair():
    private_val = int(secrets.token_hex(32), 16) % ORDER_N
    public_pt = scalar_point_multiplication(private_val, BASE_POINT)
    return private_val, public_pt


def generate_signature(private_key, msg_content, user_hash):
    merged_data = str(user_hash) + msg_content
    msg_bytes = merged_data.encode()
    digest_hash = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    hash_int = int(digest_hash, 16)

    k_input = str(private_key) + sm3.sm3_hash(func.bytes_to_list(msg_content.encode()))
    k_val = int(sha256(k_input.encode()).hexdigest(), 16)

    if k_val >= MODULUS_P:
        return None

    temp_pt = scalar_point_multiplication(k_val, BASE_POINT)
    r_val = (hash_int + temp_pt[0]) % ORDER_N
    s_val = modular_inverse(1 + private_key, ORDER_N) * (k_val - r_val * private_key) % ORDER_N
    return (r_val, s_val),k_val


def verify_signature(public_key, user_id, msg_content, signature):
    r_val, s_val = signature

    # 重新计算用户标识哈希
    user_hash = compute_identity_hash(user_id, public_key[0], public_key[1])
    merged_data = str(user_hash) + msg_content
    msg_bytes = merged_data.encode()
    digest_hash = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
    hash_int = int(digest_hash, 16)

    # 计算复合参数
    composite_val = (r_val + s_val) % ORDER_N

    # 计算中间点
    point1 = scalar_point_multiplication(s_val, BASE_POINT)
    point2 = scalar_point_multiplication(composite_val, public_key)
    result_pt = ecc_point_addition(point1, point2)

    # 验证签名
    R_val = (hash_int + result_pt[0]) % ORDER_N
    return R_val == r_val



def test_k_leakage():
    """k值泄露导致私钥破解验证"""
    priv_key, pub_key = create_key_pair()
    message = "机密合同"
    user_id = "company.com"

    # 计算Z_A
    user_hash = compute_identity_hash(user_id, pub_key[0], pub_key[1])

    (r_val, s_val), k_val=generate_signature(priv_key,message,user_hash)



    derived_priv = (k_val-s_val)*modular_inverse(r_val+s_val,ORDER_N)%ORDER_N

    # 验证推导的私钥
    print(f"原始私钥: {hex(priv_key)}")
    print(f"推导私钥: {hex(derived_priv)}")
    print(f"私钥匹配: {priv_key == derived_priv}")


def reusing_k_leakage():
    # 生成密钥对
    priv_key, pub_key = create_key_pair()
    msg1 = "重要合同001"
    msg2 = "重要合同002"
    user_id = "company.com"

    # 计算用户标识哈希Z
    user_hash = compute_identity_hash(user_id, pub_key[0], pub_key[1])

    # 创建测试用签名函数(强制使用相同k值)
    def sign_with_fixed_k(msg, user_hash, k_val):
        merged_data = str(user_hash) + msg
        msg_bytes = merged_data.encode()
        digest_hash = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
        hash_int = int(digest_hash, 16)

        temp_pt = scalar_point_multiplication(k_val, BASE_POINT)
        r_val = (hash_int + temp_pt[0]) % ORDER_N
        s_val = modular_inverse(1 + priv_key, ORDER_N) * (k_val - r_val * priv_key) % ORDER_N
        return r_val, s_val

    # 使用相同的k值对两个不同消息签名
    fixed_k = secrets.randbelow(ORDER_N)
    r1, s1 = sign_with_fixed_k(msg1, user_hash, fixed_k)
    r2, s2 = sign_with_fixed_k(msg2, user_hash, fixed_k)

    # 验证签名有效性
    assert verify_signature(pub_key, user_id, msg1, (r1, s1))
    assert verify_signature(pub_key, user_id, msg2, (r2, s2))

    # 利用两个签名推导私钥
    numerator = (s2 - s1) % ORDER_N
    denominator = (s1 - s2 + r1 - r2) % ORDER_N
    derived_priv = (numerator * modular_inverse(denominator, ORDER_N)) % ORDER_N

    # 验证推导的私钥
    print(f"原始私钥: {hex(priv_key)}")
    print(f"推导私钥: {hex(derived_priv)}")
    print(f"私钥匹配: {priv_key == derived_priv}")


def two_users_same_k_leakage():
    """两个用户使用相同k值导致私钥互推"""
    # 两个用户各自生成密钥对
    priv_key1, pub_key1 = create_key_pair()
    priv_key2, pub_key2 = create_key_pair()

    msg = "同一消息"
    user_id1 = "user1.com"
    user_id2 = "user2.com"

    # 创建测试用签名函数(强制使用相同k值)
    def sign_with_fixed_k(priv_key, pub_key, user_id, msg, k_val):
        user_hash = compute_identity_hash(user_id, pub_key[0], pub_key[1])
        merged_data = str(user_hash) + msg
        msg_bytes = merged_data.encode()
        digest_hash = sm3.sm3_hash(func.bytes_to_list(msg_bytes))
        hash_int = int(digest_hash, 16)

        temp_pt = scalar_point_multiplication(k_val, BASE_POINT)
        r_val = (hash_int + temp_pt[0]) % ORDER_N
        s_val = modular_inverse(1 + priv_key, ORDER_N) * (k_val - r_val * priv_key) % ORDER_N
        return r_val, s_val

    # 相同的k值
    fixed_k = secrets.randbelow(ORDER_N)

    # 用户1用fixed_k签名
    r1, s1 = sign_with_fixed_k(priv_key1, pub_key1, user_id1, msg, fixed_k)
    # 用户2用相同的fixed_k签名
    r2, s2 = sign_with_fixed_k(priv_key2, pub_key2, user_id2, msg, fixed_k)

    # 用户1推导用户2的私钥
    derived_priv2 = ((fixed_k - s2) * modular_inverse(s2 + r2, ORDER_N)) % ORDER_N

    # 用户2推导用户1的私钥
    derived_priv1 = ((fixed_k - s1) * modular_inverse(s1 + r1, ORDER_N)) % ORDER_N

    # 验证推导结果
    print("=== 用户1推导用户2的私钥 ===")
    print(f"用户2原始私钥: {hex(priv_key2)}")
    print(f"用户1推导私钥: {hex(derived_priv2)}")
    print(f"匹配结果: {priv_key2 == derived_priv2}")

    print("\n=== 用户2推导用户1的私钥 ===")
    print(f"用户1原始私钥: {hex(priv_key1)}")
    print(f"用户2推导私钥: {hex(derived_priv1)}")
    print(f"匹配结果: {priv_key1 == derived_priv1}")
if __name__ == "__main__":
    test_k_leakage()
    reusing_k_leakage()
    two_users_same_k_leakage()
