#include <iostream>
#include <cstring>
using namespace std;


unsigned int IV[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d ,0xb0fb0e4e };
unsigned int IV2[8] = { 0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d ,0xb0fb0e4e };
unsigned int T[2] = { 0x79cc4519 ,0x7a879d8a };
char* plaintext_after_stuffing;
int length;

unsigned int T_j(int j) {
    if (j >= 0 && j <= 15) {
        return T[0];
    }
    else {
        return T[1];
    }
}
unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int j) {
    if (j >= 0 && j <= 15) {
        return (X ^ Y ^ Z);
    }
    else {
        return ((X & Y) | (X & Z) | (Y & Z));
    }
}
unsigned int GG(unsigned int X, unsigned Y, unsigned int Z, int j) {
    if (j >= 0 && j <= 15) {
        return (X ^ Y ^ Z);
    }
    else {
        return ((X & Y) | ((~X) & Z));
    }
}
unsigned int rol(unsigned int X, int Y) {
    return (X << Y) | (X >> (32 - Y));
}

unsigned int p0(unsigned int X) {
    return X ^ rol(X, 9) ^ rol(X, 17);
}

unsigned int p1(unsigned int X) {
    return X ^ rol(X, 15) ^ rol(X, 23);
}

static void dump_buf(char* ciphertext_32, int lenth)
{
    for (int i = 0; i < lenth; i++) {
        printf("%02X ", (unsigned char)ciphertext_32[i]);
    }
    printf("\n");
}

bool compare(char* ciphertext_32_1, char* ciphertext_32_2, int lenth)
{
    for (int i = 0; i < lenth; i++) {
        if ((unsigned char)ciphertext_32_1[i] != (unsigned char)ciphertext_32_2[i])
            return false;
    }
    return true;
}

int bit_stuffing(char plaintext[], int lenth_for_plaintext) {
    long long bit_len = lenth_for_plaintext * 8;
    int the_mod_of_fin_froup = bit_len % 512;
    if (the_mod_of_fin_froup < 448) {
        int lenth_for_p_after_stuffing = (lenth_for_plaintext / 64 + 1) * 64;
        plaintext_after_stuffing = new char[lenth_for_p_after_stuffing];
        memcpy(plaintext_after_stuffing, plaintext, lenth_for_plaintext);
        plaintext_after_stuffing[lenth_for_plaintext] = (char)0x80;
        for (int i = lenth_for_plaintext + 1; i < lenth_for_p_after_stuffing - 8; i++) {
            plaintext_after_stuffing[i] = 0;
        }

        for (int i = lenth_for_p_after_stuffing - 8, j = 0; i < lenth_for_p_after_stuffing; i++, j++) {
            plaintext_after_stuffing[i] = ((char*)&bit_len)[7 - j];
        }
        return lenth_for_p_after_stuffing;
    }
    else {
        int lenth_for_p_after_stuffing = (lenth_for_plaintext / 64 + 2) * 64;
        plaintext_after_stuffing = new char[lenth_for_p_after_stuffing];
        memcpy(plaintext_after_stuffing, plaintext, lenth_for_plaintext);
        plaintext_after_stuffing[lenth_for_plaintext] = (char)0x80;
        for (int i = lenth_for_plaintext + 1; i < lenth_for_p_after_stuffing - 8; i++) {
            plaintext_after_stuffing[i] = 0;
        }

        for (int i = lenth_for_p_after_stuffing - 8, j = 0; i < lenth_for_p_after_stuffing; i++, j++) {
            plaintext_after_stuffing[i] = ((char*)&bit_len)[7 - j];
        }
        return lenth_for_p_after_stuffing;
    }
}

int bit_stuff_for_length_attack(char plaintext[], int lenth_for_plaintext, int length_for_message) {
    long long bit_len = (lenth_for_plaintext + length_for_message) * 8;
    int the_mod_of_fin_froup = bit_len % 512;
    if (the_mod_of_fin_froup < 448) {
        int lenth_for_p_after_stuffing = (lenth_for_plaintext / 64 + 1) * 64;
        plaintext_after_stuffing = new char[lenth_for_p_after_stuffing];
        memcpy(plaintext_after_stuffing, plaintext, lenth_for_plaintext);
        plaintext_after_stuffing[lenth_for_plaintext] = (char)0x80;
        for (int i = lenth_for_plaintext + 1; i < lenth_for_p_after_stuffing - 8; i++) {
            plaintext_after_stuffing[i] = 0;
        }

        for (int i = lenth_for_p_after_stuffing - 8, j = 0; i < lenth_for_p_after_stuffing; i++, j++) {
            plaintext_after_stuffing[i] = ((char*)&bit_len)[7 - j];
        }
        return lenth_for_p_after_stuffing;
    }
    else {
        int lenth_for_p_after_stuffing = (lenth_for_plaintext / 64 + 2) * 64;
        plaintext_after_stuffing = new char[lenth_for_p_after_stuffing];
        memcpy(plaintext_after_stuffing, plaintext, lenth_for_plaintext);
        plaintext_after_stuffing[lenth_for_plaintext] = (char)0x80;
        for (int i = lenth_for_plaintext + 1; i < lenth_for_p_after_stuffing - 8; i++) {
            plaintext_after_stuffing[i] = 0;
        }

        for (int i = lenth_for_p_after_stuffing - 8, j = 0; i < lenth_for_p_after_stuffing; i++, j++) {
            plaintext_after_stuffing[i] = ((char*)&bit_len)[7 - j];
        }
        return lenth_for_p_after_stuffing;
    }
}

void CF(unsigned int* IV, int* p_a_f) {
    unsigned int W[68];
    unsigned int W_t[64];
    for (int i = 0; i < 16; i++)
    {
        W[i] = ((unsigned int)p_a_f[i] & 0x000000FFU) << 24 |
            ((unsigned int)p_a_f[i] & 0x0000FF00U) << 8 |
            ((unsigned int)p_a_f[i] & 0x00FF0000U) >> 8 |
            ((unsigned int)p_a_f[i] & 0xFF000000U) >> 24;
    }
    for (int i = 16; i < 68; i++)
    {
        W[i] = p1(W[i - 16] ^ W[i - 9] ^ rol(W[i - 3], 15)) ^ rol(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; i++) {
        W_t[i] = W[i] ^ W[i + 4];
    }
    unsigned int A = IV[0], B = IV[1], C = IV[2], D = IV[3], E = IV[4], F = IV[5], G = IV[6], H = IV[7];
    for (int i = 0; i < 64; i++) {
        unsigned int temp = rol(A, 12) + E + rol(T_j(i), i % 32);
        unsigned int SS1 = rol(temp, 7);
        unsigned int SS2 = SS1 ^ rol(A, 12);
        unsigned int TT1 = FF(A, B, C, i) + D + SS2 + W_t[i];
        unsigned int TT2 = GG(E, F, G, i) + H + SS1 + W[i];
        D = C;
        C = rol(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = rol(F, 19);
        F = E;
        E = p0(TT2);
    }
    IV[0] = A ^ IV[0]; IV[1] = B ^ IV[1]; IV[2] = C ^ IV[2]; IV[3] = D ^ IV[3];
    IV[4] = E ^ IV[4]; IV[5] = F ^ IV[5]; IV[6] = G ^ IV[6]; IV[7] = H ^ IV[7];
}

void sm3(char plaintext[], unsigned int* hash_val, int lenth_for_plaintext) {
    int n = bit_stuffing(plaintext, lenth_for_plaintext) / 64;
    for (int i = 0; i < n; i++) {
        CF(IV, (int*)&plaintext_after_stuffing[i * 64]);
    }
    for (int i = 0; i < 8; i++) {
        hash_val[i] = IV[i];
    }
    memcpy(IV, IV2, 8 * sizeof(unsigned int));
}

void sm3_for_length_attack(char plaintext[], unsigned int* hash_val, int lenth_for_plaintext, int length_for_message) {
    int n = bit_stuff_for_length_attack(plaintext, lenth_for_plaintext, length_for_message) / 64;
    for (int i = 0; i < n; i++) {
        CF(IV, (int*)&plaintext_after_stuffing[i * 64]);
    }
    for (int i = 0; i < 8; i++) {
        hash_val[i] = IV[i];
    }
    memcpy(IV, IV2, 8 * sizeof(unsigned int));
}

int sm3_length_attack(char* mem_append, unsigned int* temp, unsigned int* hash_val, int length_formemappend, int length_for_message) {
    memcpy(IV, hash_val, 8 * sizeof(unsigned int));
    unsigned int new_hash_val[8];
    sm3_for_length_attack(mem_append, new_hash_val, length_formemappend, length_for_message);

    cout << "The hash obtained by the length extension attack:" << endl;
    dump_buf((char*)new_hash_val, 32);
    if (compare((char*)temp, (char*)new_hash_val, 32))
        cout << "The length attack succeeded" << endl;
    else
        cout << "The length attack failed" << endl;
    return 0;
}

int main() {
    char m[] = "202200460066";
    unsigned int hash_val[8];
    unsigned int hash_val2[8];
    sm3(m, hash_val, 3);
    cout << "Original hash of '202':" << endl;
    dump_buf((char*)hash_val, 32);

    bit_stuffing(m, 3);
    char plaintext_for_length_attack[67];
    memcpy(plaintext_for_length_attack, plaintext_after_stuffing, 64);
    char memappend[] = "zzx";
    memcpy(&plaintext_for_length_attack[64], memappend, 3);

    sm3(plaintext_for_length_attack, hash_val2, 67);
    cout << "Manually filled message and its hash:" << endl;
    dump_buf((char*)hash_val2, 32);

    sm3_length_attack(memappend, hash_val2, hash_val, 3, 64);
    return 0;
}