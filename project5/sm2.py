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
    return (r_val, s_val)


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


def test_sm2_signature():
    test_cases = [
        {"user_id": "user_12345", "message": "重要的数字证书申请"},
        {"user_id": "admin@org.com", "message": "系统配置文件备份"},
        {"user_id": "device_abc", "message": "固件升级请求"}
    ]

    for idx, test_case in enumerate(test_cases, 1):
        print(f"\n=== 测试案例 #{idx} ===")
        print(f"用户ID: {test_case['user_id']}")
        print(f"消息内容: {test_case['message']}")

        priv_key, pub_key = create_key_pair()
        print(f"生成的公钥: ({hex(pub_key[0])}, {hex(pub_key[1])})")

        user_hash_val = compute_identity_hash(
            test_case['user_id'], pub_key[0], pub_key[1]
        )

        # 确保成功生成有效签名
        sig = generate_signature(priv_key, test_case['message'], user_hash_val)
        while sig is None:
            priv_key, pub_key = create_key_pair()
            user_hash_val = compute_identity_hash(
                test_case['user_id'], pub_key[0], pub_key[1]
            )
            sig = generate_signature(priv_key, test_case['message'], user_hash_val)

        print(f"签名结果: r={hex(sig[0])}, s={hex(sig[1])}")

        # 验证签名
        verification = verify_signature(
            pub_key, test_case['user_id'], test_case['message'], sig
        )
        status = "成功" if verification else "失败"
        print(f"签名验证状态: {status}")

        


if __name__ == "__main__":
    test_sm2_signature()
