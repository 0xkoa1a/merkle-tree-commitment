/* 手写 SHA3-256。state[x][y]、轮次及字节次序与 sha3.py 相同。
 * 每次 digest 只跨一次 Python/C 接口；保持 GIL，不调用外部哈希库。 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

#define RATE_BYTES 136
#define DIGEST_BYTES 32

static const unsigned ROTATION_OFFSETS[5][5] = {
    {0, 36, 3, 41, 18}, {1, 44, 10, 45, 2}, {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56}, {27, 20, 39, 8, 14}
};

static const uint64_t ROUND_CONSTANTS[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808A), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808B), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008A), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000A),
    UINT64_C(0x000000008000808B), UINT64_C(0x800000000000008B),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800A), UINT64_C(0x800000008000000A),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

static uint64_t rotl64(uint64_t value, unsigned shift)
{
    /* shift=0 时直接返回，避免 C 中移位 64 位的未定义行为。 */
    return shift == 0 ? value : (value << shift) | (value >> (64 - shift));
}

static uint64_t load_le64(const unsigned char *bytes)
{
    /* 逐字节读取，不依赖输入对齐、主机端序或指针类型转换。 */
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) {
        value |= (uint64_t)bytes[i] << (8 * i);
    }
    return value;
}

static void keccak_f1600(uint64_t state[5][5])
{
    for (unsigned round = 0; round < 24; ++round) {
        uint64_t column_xors[5], theta_mix[5], rotated[5][5];
        /* θ：列异或，再混入相邻列。 */
        for (unsigned x = 0; x < 5; ++x) {
            column_xors[x] = state[x][0] ^ state[x][1] ^ state[x][2]
                            ^ state[x][3] ^ state[x][4];
        }
        for (unsigned x = 0; x < 5; ++x) {
            theta_mix[x] = column_xors[(x + 4) % 5]
                         ^ rotl64(column_xors[(x + 1) % 5], 1);
        }
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                state[x][y] ^= theta_mix[x];
            }
        }
        /* ρ + π：旋转每个 lane 后换位。 */
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                rotated[y][(2 * x + 3 * y) % 5] =
                    rotl64(state[x][y], ROTATION_OFFSETS[x][y]);
            }
        }
        /* χ：uint64_t 的取反自然限制在 64 位内。 */
        for (unsigned x = 0; x < 5; ++x) {
            for (unsigned y = 0; y < 5; ++y) {
                state[x][y] = rotated[x][y]
                    ^ (~rotated[(x + 1) % 5][y] & rotated[(x + 2) % 5][y]);
            }
        }
        /* ι：本轮常数混入 (0,0)。 */
        state[0][0] ^= ROUND_CONSTANTS[round];
    }
}

static void absorb_block(uint64_t state[5][5], const unsigned char *block)
{
    /* lane 编号 x+5*y；136 B 正好是 17 个 lane。 */
    for (unsigned lane = 0; lane < RATE_BYTES / 8; ++lane) {
        state[lane % 5][lane / 5] ^= load_le64(block + 8 * lane);
    }
    keccak_f1600(state);
}

static PyObject *digest(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *message;
    static char *keywords[] = {"message", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:sha3_256_digest", keywords, &message)) {
        return NULL;
    }
    if (!PyBytes_Check(message)) {
        PyErr_SetString(PyExc_TypeError, "message must be bytes");
        return NULL;
    }

    const unsigned char *input = (const unsigned char *)PyBytes_AS_STRING(message);
    Py_ssize_t remaining = PyBytes_GET_SIZE(message);
    uint64_t state[5][5] = {{0}};
    while (remaining >= RATE_BYTES) {
        absorb_block(state, input);
        input += RATE_BYTES;
        remaining -= RATE_BYTES;
    }

    /* 整块输入也要额外吸收一个填充块；135 B 余量时后缀合成 0x86。 */
    unsigned char tail[RATE_BYTES] = {0};
    memcpy(tail, input, (size_t)remaining);
    tail[remaining] = 0x06;
    tail[RATE_BYTES - 1] |= 0x80;
    absorb_block(state, tail);

    unsigned char output[DIGEST_BYTES];
    for (unsigned i = 0; i < DIGEST_BYTES; ++i) {
        unsigned lane = i / 8;
        output[i] = (unsigned char)(state[lane % 5][lane / 5] >> (8 * (i % 8)));
    }
    return PyBytes_FromStringAndSize((const char *)output, DIGEST_BYTES);
}

static PyMethodDef methods[] = {
    {"digest", (PyCFunction)digest, METH_VARARGS | METH_KEYWORDS,
     "digest(message: bytes) -> bytes: handwritten SHA3-256, 32-byte result."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_sha3_c", "Handwritten C11 SHA3-256.", -1, methods
};

PyMODINIT_FUNC PyInit__sha3_c(void)
{
    PyObject *result = PyModule_Create(&module);
    if (result == NULL) {
        return NULL;
    }
    PyObject *info = Py_BuildValue("{s:s,s:s}", "compiler", __VERSION__,
                                   "compile_flags", MTC_BUILD_FLAGS);
    if (info == NULL || PyModule_AddObject(result, "BUILD_INFO", info) < 0) {
        Py_XDECREF(info);
        Py_DECREF(result);
        return NULL;
    }
    return result;
}
