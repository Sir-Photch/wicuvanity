#include <curand_kernel.h>
#include <cxxopts.hpp>
#include <iostream>
#include <stdio.h>

typedef int64_t i64;
typedef i64 field_elem[16];
typedef unsigned char u8;

__device__ void toBase64(const u8 in[32], char out[45]) {
    static const char* b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t i, j, v;

    for (i = 0, j = 0; i < 32; i += 3, j += 4) {
        v = in[i];
        v = i + 1 < 32 ? v << 8 | in[i + 1] : v << 8;
        v = i + 2 < 32 ? v << 8 | in[i + 2] : v << 8;

        out[j] = b64chars[(v >> 18) & 0x3F];
        out[j + 1] = b64chars[(v >> 12) & 0x3F];
        if (i + 1 < 32) {
            out[j + 2] = b64chars[(v >> 6) & 0x3F];
        } else {
            out[j + 2] = '=';
        }
        if (i + 2 < 32) {
            out[j + 3] = b64chars[v & 0x3F];
        } else {
            out[j + 3] = '=';
        }
    }
    out[44] = '\0';
}

// https://martin.kleppmann.com/papers/curve25519.pdf

__device__ void unpack25519(field_elem out, const u8 in[32]) {
    int i;
    for (i = 0; i < 16; i++) {
        out[i] = in[2 * i] + ((int64_t)in[2 * i + 1] << 8);
    }
    out[15] &= 0x7fff;
}

__device__ void swap25519(field_elem p, field_elem q, int bit) {
    i64 t, i, c = ~(bit - 1);
    for (i = 0; i < 16; i++) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

__device__ void field_elem_add(field_elem out, const field_elem a, const field_elem b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] + b[i];
    }
}

__device__ void field_elem_sub(field_elem out, const field_elem a, const field_elem b) {
    for (int i = 0; i < 16; i++) {
        out[i] = a[i] - b[i];
    }
}

__device__ void carry25519(field_elem elem) {
    int i;
    i64 carry;
    for (i = 0; i < 16; ++i) {
        carry = elem[i] >> 16;
        elem[i] -= carry << 16;
        if (i < 15) {
            elem[i + 1] += carry;
        } else {
            elem[0] += 38 * carry;
        }
    }
}

__device__ void field_elem_mul(field_elem out, const field_elem a, const field_elem b) {
    i64 i, j, product[31];
    for (i = 0; i < 31; i++) {
        product[i] = 0;
    }
    for (i = 0; i < 16; i++) {
        for (j = 0; j < 16; j++) {
            product[i + j] += a[i] * b[j];
        }
    }
    for (i = 0; i < 15; i++) {
        product[i] += 38 * product[i + 16];
    }
    for (i = 0; i < 16; i++) {
        out[i] = product[i];
    }
    carry25519(out);
    carry25519(out);
}

__device__ void field_elem_inv(field_elem out, const field_elem in) {
    field_elem c;
    int i;
    for (i = 0; i < 16; ++i) {
        c[i] = in[i];
    }
    for (i = 253; i >= 0; --i) {
        field_elem_mul(c, c, c);
        if (i != 2 && i != 4) {
            field_elem_mul(c, c, in);
        }
    }
    for (i = 0; i < 16; ++i) {
        out[i] = c[i];
    }
}

__device__ void pack25519(u8 out[32], const field_elem in) {
    int i, j, carry;
    field_elem m, t;
    for (i = 0; i < 16; ++i) {
        t[i] = in[i];
    }
    carry25519(t);
    carry25519(t);
    carry25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        carry = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        swap25519(t, m, 1 - carry);
    }
    for (i = 0; i < 16; ++i) {
        out[2 * i] = t[i] & 0xff;
        out[2 * i + 1] = t[i] >> 8;
    }
}

__device__ void genpub(const u8 privkey[32], u8 pub[32]) {
    static const field_elem _121665 = { 0xDB41, 1 };
    static const u8 _9[32] = { 9 };

    u8 clamped[32];
    i64 bit, i;
    field_elem a, b, c, d, e, f, x;
    for (i = 0; i < 32; i++) {
        clamped[i] = privkey[i];
    }
    clamped[0] &= 0xf8;
    clamped[31] = (clamped[31] & 0x7f) | 0x40;
    unpack25519(x, _9);
    for (i = 0; i < 16; ++i) {
        b[i] = x[i];
        d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
        bit = (clamped[i >> 3] >> (i & 7)) & 1;
        swap25519(a, b, bit);
        swap25519(c, d, bit);
        field_elem_add(e, a, c);
        field_elem_sub(a, a, c);
        field_elem_add(c, b, d);
        field_elem_sub(b, b, d);
        field_elem_mul(d, e, e);
        field_elem_mul(f, a, a);
        field_elem_mul(a, c, a);
        field_elem_mul(c, b, e);
        field_elem_add(e, a, c);
        field_elem_sub(a, a, c);
        field_elem_mul(b, a, a);
        field_elem_sub(c, d, f);
        field_elem_mul(a, c, _121665);
        field_elem_add(a, a, d);
        field_elem_mul(c, c, a);
        field_elem_mul(a, d, f);
        field_elem_mul(d, b, x);
        field_elem_mul(b, e, e);
        swap25519(a, b, bit);
        swap25519(c, d, bit);
    }
    field_elem_inv(c, c);
    field_elem_mul(a, a, c);
    pack25519(pub, a);
}

__device__ char cutolower(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

__device__ size_t custrlen(const char* s) {
    size_t i = 0;
    while (s[i] != '\0') {
        i++;
    }
    return i;
}

__device__ int custrncasecmp(const char* s1, const char* s2, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (cutolower(s1[i]) != cutolower(s2[i])) {
            return 1;
        }
    }
    return 0;
}

__device__ char* custrcasestr(const char* haystack, const char* needle) {
    char c, sc;
    size_t len;
    if ((c = *needle++) != 0) {
        c = cutolower((unsigned char)c);
        len = custrlen(needle);
        do {
            do {
                if ((sc = *haystack++) == 0) {
                    return (NULL);
                }
            } while ((char)cutolower((unsigned char)sc) != c);
        } while (custrncasecmp(haystack, needle, len) != 0);
        haystack--;
    }
    return ((char*)haystack);
}

__global__ void generator(const char* _needle, size_t needlesize, int in) {
    int tid = threadIdx.x, idx = blockIdx.x * blockDim.x + tid;

    extern __shared__ char needle[];

    if (tid < needlesize) {
        needle[tid] = _needle[tid];
    } else if (tid == needlesize) {
        needle[tid] = '\0';
    }

    __syncthreads();

    curandState_t state;
    curand_init(0, idx, 0, &state);

    u8 privkey[32], pubkey[32];
    char privkey_b64[45], pubkey_b64[45];

    while (true) {
        for (int i = 0; i < 32; i++) {
            privkey[i] = curand(&state) % 256;
        }

        genpub(privkey, pubkey);

        toBase64(pubkey, pubkey_b64);

        char save = pubkey_b64[in];
        pubkey_b64[in] = '\0';
        if (custrcasestr(pubkey_b64, needle) != NULL) {
            pubkey_b64[in] = save;
            toBase64(privkey, privkey_b64);
            printf("private: %s | public: %s\n", privkey_b64, pubkey_b64);
        }
    }
}

int main(int argc, char** argv) {
    cxxopts::Options options(
        "wicuvanity",
        "Generate wireguard private and public keys with a specific public key prefix"
    );

    options.add_options()("needle", "needle to find", cxxopts::value<std::string>())
                       ("in", "needle in first ... characters", cxxopts::value<int>()->default_value("10"))
                       ("gridsize", "Number of blocks", cxxopts::value<int>()->default_value("1024"))
                       ("blocksize", "Number of threads in block", cxxopts::value<int>()->default_value("256"))
                       ("h,help", "print usage");

    options.parse_positional({ "needle" });
    options.positional_help("needle");

    auto result = options.parse(argc, argv);

    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    auto needle = result["needle"].as<std::string>();
    char *pndl_host = const_cast<char*>(needle.c_str()), *pndl_dev;

    cudaHostRegister(pndl_host, needle.size(), cudaHostRegisterReadOnly);
    cudaHostGetDevicePointer(&pndl_dev, pndl_host, 0);

    int gridsize = result["gridsize"].as<int>(), blocksize = result["blocksize"].as<int>(),
        needlesize = needle.size(), in = result["in"].as<int>();

    if (blocksize < needlesize) {
        std::cerr << "Error: block size must be greater than needle size" << std::endl;
        return 1;
    }

    generator<<<gridsize, blocksize, needlesize + 1>>>(pndl_dev, needlesize, in);
    cudaDeviceSynchronize();

    cudaHostUnregister(pndl_host);

    cudaError_t code;
    switch (code = cudaGetLastError()) {
        case cudaSuccess:
            return 0;
        case cudaErrorLaunchOutOfResources:
            std::cerr << "Error: out of resources. Try decreasing --blocksize to " << blocksize - 32
                      << std::endl;
            return 1;
        default:
            std::cerr << "Error: " << cudaGetErrorString(code) << std::endl;
            return 1;
    }
}
