#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}


int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t low = (uint32_t)challenge;
    uint32_t mid = (uint32_t)(challenge >> 16);
    uint32_t high = (uint32_t)(challenge >> 32);
    uint32_t a = (low + 4 * mid) ^ 0x5a0;
    uint32_t b = (low ^ 0xfb73) + 8 * high;
    uint32_t values[1] = {a ^ (b + 0x46fa)};
    return write_answer(out, cap, values, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[6];
    values[0] = ((uint32_t)(challenge >> 5) & 31) + 16;
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t a = (uint32_t)(challenge >> (8 + 2 * i)) & 31;
        values[i] = 2 * values[i - 1] + (a ^ i);
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[2];
    uint32_t x = (uint32_t)(challenge >> 3) ^ (uint32_t)(challenge >> 32);
    values[0] = (uint32_t)challenge & 7u;
    switch (values[0]) {
        case 0: values[1] = x * 5u + 0x4f19u; break;
        case 1: values[1] = x * 3u + 0x3a75u; break;
        case 2: values[1] = (x ^ 0x643u) + (x >> 1); break;
        case 3: values[1] = (x << 2) ^ 0x7b03u; break;
        case 4: values[1] = (x ^ 0xd854u) + (x >> 1); break;
        case 5: values[1] = (x << 2) ^ 0x7d53u; break;
        case 6: values[1] = x * 5u + 0x26cb4u; break;
        default: values[1] = x * 5u + 0x4385au; break;
    }
    return write_answer(out, cap, values, 2);
}

static uint32_t walk4(uint32_t x, uint32_t l, uint32_t r, uint32_t k) {
    uint32_t m = l + ((r - l) >> 1);
    uint32_t a;
    if (x == m) return (m + 0x68u) ^ k;
    if (x < m) {
        a = walk4(x, l, m - 1u, k);
        return (a * 5u) ^ (m + k) ^ 0x1fu;
    }
    a = walk4(x, m + 1u, r, k);
    return (a * 5u) ^ (m + k) ^ 0x17u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t x = (uint32_t)challenge & 127u;
    uint32_t k = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    uint32_t values[1] = {walk4(x, 0, 127, k)};
    return write_answer(out, cap, values, 1);
}

static uint32_t phase6_op(unsigned op, uint32_t x) {
    switch (op) {
        case 0: return (x >> 7) | (x << 25);
        case 1: return (2 * x + 0xb13cU) ^ (7 * x);
        case 2: return (x ^ (x >> 5)) + 0xf09aU;
        case 3: return (x + 0x484bU) ^ (x >> 5);
        case 4: return ((x << 1) | (x >> 31)) ^ 0x7481U;
        default: return (x ^ 0x85d4U) + 4 * x;
    }
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    static const unsigned heads[8] = {11, 9, 3, 5, 6, 10, 1, 0};
    static const struct {
        uint32_t value;
        uint32_t tag;
        int next;
    } nodes[12] = {
        {0x8b35U, 0x0032U, 7},
        {0x897fU, 0x0a5cU, 0},
        {0xdfc8U, 0x0276U, 4},
        {0x0220U, 0x073bU, 5},
        {0x750bU, 0x0b56U, -1},
        {0xfae6U, 0x0434U, 6},
        {0x0236U, 0x0632U, 10},
        {0x032dU, 0x0320U, 8},
        {0xb26aU, 0x083dU, 2},
        {0x128aU, 0x0146U, 3},
        {0xe9e6U, 0x091fU, 1},
        {0xdf1fU, 0x053dU, 9}
    };
    uint32_t values[2] = {0};
    uint32_t sum = (uint32_t)(challenge >> 6)
                 ^ (uint32_t)(challenge >> 32) ^ 0xbf49U;
    unsigned steps = 1 + (unsigned)((challenge >> 3) & 3);
    int node = (int)heads[challenge & 7];
    for (unsigned i = 0; i < steps; ++i) {
        sum = (3 * sum + nodes[node].value) ^ nodes[node].tag;
        values[1] = nodes[node].tag;
        node = nodes[node].next;
    }
    values[0] = sum;
    return write_answer(out, cap, values, 2);
}

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    static const unsigned ops[8] = {1, 3, 2, 2, 4, 3, 0, 5};
    uint32_t x = (uint32_t)(challenge >> 6)
               ^ (uint32_t)(challenge >> 32);
    x = phase6_op(ops[challenge & 7], x) ^ 0xcb24U;
    x = phase6_op(ops[(challenge >> 3) & 7], x) + 0x953eU;
    uint32_t values[1] = {x};
    return write_answer(out, cap, values, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t kind = context & 3;
    uint32_t a = (uint32_t)challenge ^ (uint32_t)(challenge >> 32);
    uint32_t b = (uint32_t)context ^ (uint32_t)(context >> 32);
    uint32_t x = ((a ^ b) * 5 + 0xfca2) ^ 0x525b;
    uint32_t y = x ^ (kind * 0xfca2) ^ (uint32_t)(context >> 16);
    uint32_t z = y ^ (b + kind + 0x525b + (a >> 7));
    int size = snprintf(out, cap,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN%" PRIu32 " %" PRIu32 " %" PRIu32,
        kind, y, z);
    return size < 0 || (size_t)size >= cap;
}
