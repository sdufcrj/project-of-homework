
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <immintrin.h>
#include <time.h>

#define MAX_LEN (2 << 12) 
#define sm3_digest_BYTES 32
#define sm3_block_BYTES 64
#define sm3_hmac_BYTES sm3_digest_BYTES

// 循环左移宏
#define rol(x, j) (((x) << (j)) | ((uint32_t)(x) >> (32 - (j))))

// 置换函数
#define P0(x) ((x) ^ rol((x), 9) ^ rol((x), 17))
#define P1(x) ((x) ^ rol((x), 15) ^ rol((x), 23))

// 布尔函数
#define FF0(x, y, z) ((x) ^ (y) ^ (z))
#define FF1(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG0(x, y, z) ((x) ^ (y) ^ (z))
#define GG1(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

// SIMD辅助宏
#define simd_rol(x, k) _mm_or_si128(_mm_slli_epi32(x, k), _mm_srli_epi32(x, 32 - k))

// 字节交换
#define byte_swap32(x) (((x) & 0xff000000) >> 24) | \
                       (((x) & 0x00ff0000) >> 8)  | \
                       (((x) & 0x0000ff00) << 8)  | \
                       (((x) & 0x000000ff) << 24)

// 上下文结构
typedef struct sm3_ctx_t {
    uint32_t digest[sm3_digest_BYTES / sizeof(uint32_t)];
    int nblocks;  // 已处理的块数
    uint8_t block[sm3_block_BYTES];
    int num;       // 当前块中的字节数
} sm3_ctx;

// 函数声明
void sm3_init(sm3_ctx* ctx);
void sm3_update(sm3_ctx* ctx, const uint8_t* data, size_t data_len);
void sm3_final(sm3_ctx* ctx, uint8_t* digest);
void sm3(const uint8_t* message, size_t mlen, uint8_t res[sm3_digest_BYTES]);
static void sm3_compress(uint32_t digest[sm3_digest_BYTES / sizeof(uint32_t)], const uint8_t block[sm3_block_BYTES]);

// T表初始化
static void T_init(uint32_t T[64]) {
    for (int i = 0; i < 16; i++) {
        T[i] = 0x79CC4519;
    }
    for (int i = 16; i < 64; i++) {
        T[i] = 0x7A879D8A;
    }
}

// SM3初始化
void sm3_init(sm3_ctx* ctx) {
    ctx->digest[0] = 0x7380166F;
    ctx->digest[1] = 0x4914B2B9;
    ctx->digest[2] = 0x172442D7;
    ctx->digest[3] = 0xDA8A0600;
    ctx->digest[4] = 0xA96F30BC;
    ctx->digest[5] = 0x163138AA;
    ctx->digest[6] = 0xE38DEE4D;
    ctx->digest[7] = 0xB0FB0E4E;

    ctx->nblocks = 0;
    ctx->num = 0;
}


void sm3_update(sm3_ctx* ctx, const uint8_t* data, size_t dlen) {
    if (ctx->num) {
        unsigned int left = sm3_block_BYTES - ctx->num;
        if (dlen < left) {
            memcpy(ctx->block + ctx->num, data, dlen);
            ctx->num += dlen;
            return;
        }
        else {
            memcpy(ctx->block + ctx->num, data, left);
            sm3_compress(ctx->digest, ctx->block);
            ctx->nblocks++;
            data += left;
            dlen -= left;
        }
    }
    while (dlen >= sm3_block_BYTES) {
        sm3_compress(ctx->digest, data);
        ctx->nblocks++;
        data += sm3_block_BYTES;
        dlen -= sm3_block_BYTES;
    }
    ctx->num = dlen;
    if (dlen) {
        memcpy(ctx->block, data, dlen);
    }
}


void sm3_final(sm3_ctx* ctx, uint8_t* digest) {
    size_t i;
    uint32_t* pdigest = (uint32_t*)(digest);
    uint64_t* count = (uint64_t*)(ctx->block + sm3_block_BYTES - 8);

    ctx->block[ctx->num] = 0x80;

    if (ctx->num + 9 <= sm3_block_BYTES) {
        memset(ctx->block + ctx->num + 1, 0, sm3_block_BYTES - ctx->num - 9);
    }
    else {
        memset(ctx->block + ctx->num + 1, 0, sm3_block_BYTES - ctx->num - 1);
        sm3_compress(ctx->digest, ctx->block);
        memset(ctx->block, 0, sm3_block_BYTES - 8);
    }

    count[0] = (uint64_t)(ctx->nblocks) * 512 + (ctx->num << 3);
    count[0] = __builtin_bswap64(count[0]);

    sm3_compress(ctx->digest, ctx->block);
    for (i = 0; i < sizeof(ctx->digest) / sizeof(ctx->digest[0]); i++) {
        pdigest[i] = __builtin_bswap32(ctx->digest[i]);
    }
    memset(ctx, 0, sizeof(sm3_ctx));
}


static void sm3_compress(uint32_t digest[8], const uint8_t block[64]) {
    uint32_t T[64];
    T_init(T);

    uint32_t W0[68], W1[64];
    const uint32_t* pblock = (const uint32_t*)(block);

    // 加载并字节交换
    for (int i = 0; i < 16; i++) {
        W0[i] = __builtin_bswap32(pblock[i]);
    }

    // 消息扩展
    for (int i = 16; i < 68; i++) {
        W0[i] = P1(W0[i - 16] ^ W0[i - 9] ^ rol(W0[i - 3], 15)) ^ rol(W0[i - 13], 7) ^ W0[i - 6];
    }

    // 使用SIMD计算W1
    for (int i = 0; i < 64; i += 4) {
        __m128i w0_i = _mm_loadu_si128((__m128i*)(W0 + i));
        __m128i w0_i4 = _mm_loadu_si128((__m128i*)(W0 + i + 4));
        __m128i w1 = _mm_xor_si128(w0_i, w0_i4);
        _mm_storeu_si128((__m128i*)(W1 + i), w1);
    }

    uint32_t A = digest[0], B = digest[1], C = digest[2], D = digest[3];
    uint32_t E = digest[4], F = digest[5], G = digest[6], H = digest[7];
    uint32_t SS1, SS2, TT1, TT2;

    // 迭代计算
    for (int j = 0; j < 16; j++) {
        SS1 = rol(rol(A, 12) + E + rol(T[j], j), 7);
        SS2 = SS1 ^ rol(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W1[j];
        TT2 = GG0(E, F, G) + H + SS1 + W0[j];
        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }

    for (int j = 16; j < 64; j++) {
        SS1 = rol(rol(A, 12) + E + rol(T[j], j % 32), 7);
        SS2 = SS1 ^ rol(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W1[j];
        TT2 = GG1(E, F, G) + H + SS1 + W0[j];
        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = P0(TT2);
    }

    digest[0] ^= A;
    digest[1] ^= B;
    digest[2] ^= C;
    digest[3] ^= D;
    digest[4] ^= E;
    digest[5] ^= F;
    digest[6] ^= G;
    digest[7] ^= H;
}


void sm3(const uint8_t* message, size_t mlen, uint8_t res[sm3_digest_BYTES]) {
    sm3_ctx ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, message, mlen);
    sm3_final(&ctx, res);
}


static double get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main() {
    uint8_t hash[32] = {};
    uint8_t message[MAX_LEN] = "202200460066";
    size_t len = strlen((char*)message);

    sm3(message, len, hash);


    int test_runs = 1000;
    double total_time = 0.0;
    double start_time, end_time;

    for (int i = 0; i < test_runs; i++) {
        start_time = get_current_time();
        sm3(message, len, hash);
        end_time = get_current_time();
        total_time += (end_time - start_time);
    }


    printf("SM3 Hash: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    double avg_time = total_time / test_runs;
    double throughput = (double)len / avg_time;

    printf("\nPerformance Metrics:\n");
    printf("Test Runs: %d\n", test_runs);
    printf("Total Time: %.6f seconds\n", total_time);
    printf("Average Time: %.9f seconds\n", avg_time);
    printf("Throughput: %.2f MB/s\n", throughput / (1024 * 1024));

    return 0;
}