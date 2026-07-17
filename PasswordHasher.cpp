#include "PasswordHasher.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <array>
#include <vector>

static uint32_t rotateRight(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32 - count));
}

static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

static uint32_t sigma0(uint32_t x) {
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

static uint32_t sigma1(uint32_t x) {
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

static uint32_t delta0(uint32_t x) {
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

static uint32_t delta1(uint32_t x) {
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

static std::array<uint8_t, 32> sha256Digest(const std::string& input) {
    static const std::array<uint32_t, 64> k = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    std::vector<uint8_t> data(input.begin(), input.end());
    uint64_t bitLen = static_cast<uint64_t>(data.size()) * 8;
    data.push_back(0x80);
    while ((data.size() % 64) != 56) {
        data.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        data.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xFF));
    }

    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    for (size_t chunk = 0; chunk < data.size(); chunk += 64) {
        std::array<uint32_t, 64> w;
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(data[chunk + i * 4]) << 24) |
                   (static_cast<uint32_t>(data[chunk + i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(data[chunk + i * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(data[chunk + i * 4 + 3]));
        }
        for (int i = 16; i < 64; ++i) {
            w[i] = delta1(w[i - 2]) + w[i - 7] + delta0(w[i - 15]) + w[i - 16];
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = h + sigma1(e) + choose(e, f, g) + k[i] + w[i];
            uint32_t t2 = sigma0(a) + majority(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    std::array<uint8_t, 32> digest;
    digest[0] = static_cast<uint8_t>((h0 >> 24) & 0xFF);
    digest[1] = static_cast<uint8_t>((h0 >> 16) & 0xFF);
    digest[2] = static_cast<uint8_t>((h0 >> 8) & 0xFF);
    digest[3] = static_cast<uint8_t>(h0 & 0xFF);
    digest[4] = static_cast<uint8_t>((h1 >> 24) & 0xFF);
    digest[5] = static_cast<uint8_t>((h1 >> 16) & 0xFF);
    digest[6] = static_cast<uint8_t>((h1 >> 8) & 0xFF);
    digest[7] = static_cast<uint8_t>(h1 & 0xFF);
    digest[8] = static_cast<uint8_t>((h2 >> 24) & 0xFF);
    digest[9] = static_cast<uint8_t>((h2 >> 16) & 0xFF);
    digest[10] = static_cast<uint8_t>((h2 >> 8) & 0xFF);
    digest[11] = static_cast<uint8_t>(h2 & 0xFF);
    digest[12] = static_cast<uint8_t>((h3 >> 24) & 0xFF);
    digest[13] = static_cast<uint8_t>((h3 >> 16) & 0xFF);
    digest[14] = static_cast<uint8_t>((h3 >> 8) & 0xFF);
    digest[15] = static_cast<uint8_t>(h3 & 0xFF);
    digest[16] = static_cast<uint8_t>((h4 >> 24) & 0xFF);
    digest[17] = static_cast<uint8_t>((h4 >> 16) & 0xFF);
    digest[18] = static_cast<uint8_t>((h4 >> 8) & 0xFF);
    digest[19] = static_cast<uint8_t>(h4 & 0xFF);
    digest[20] = static_cast<uint8_t>((h5 >> 24) & 0xFF);
    digest[21] = static_cast<uint8_t>((h5 >> 16) & 0xFF);
    digest[22] = static_cast<uint8_t>((h5 >> 8) & 0xFF);
    digest[23] = static_cast<uint8_t>(h5 & 0xFF);
    digest[24] = static_cast<uint8_t>((h6 >> 24) & 0xFF);
    digest[25] = static_cast<uint8_t>((h6 >> 16) & 0xFF);
    digest[26] = static_cast<uint8_t>((h6 >> 8) & 0xFF);
    digest[27] = static_cast<uint8_t>(h6 & 0xFF);
    digest[28] = static_cast<uint8_t>((h7 >> 24) & 0xFF);
    digest[29] = static_cast<uint8_t>((h7 >> 16) & 0xFF);
    digest[30] = static_cast<uint8_t>((h7 >> 8) & 0xFF);
    digest[31] = static_cast<uint8_t>(h7 & 0xFF);
    return digest;
}

static std::string toHex(const std::array<uint8_t, 32>& digest) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t byte : digest) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::string PasswordHasher::createSalt() {
    std::random_device rd;
    std::mt19937_64 generator(rd());
    std::uniform_int_distribution<int> distribution(0, 15);
    std::stringstream ss;
    for (int i = 0; i < 16; ++i) {
        ss << std::hex << distribution(generator);
    }
    return ss.str();
}

std::string PasswordHasher::sha256(const std::string& input) {
    return toHex(sha256Digest(input));
}

std::string PasswordHasher::hashPassword(const std::string& password, const std::string& salt) {
    return sha256(password + salt);
}

bool PasswordHasher::verifyPassword(const std::string& password, const std::string& salt, const std::string& hash) {
    return hashPassword(password, salt) == hash;
}
