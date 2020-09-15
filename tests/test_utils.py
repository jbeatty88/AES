from utils import bit_count, get_msb


def test_bit_count():
    assert(bit_count(0xae) == 5)
    assert(bit_count(0xf7) == 7)
    assert(bit_count(0x2b7e151628aed2a6abf7158809cf4f3c) == 65)
    assert(bit_count(0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b) == 94)
    assert(bit_count(0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4) == 124)

def test_get_msb():
    assert get_msb(0x2b7e151628aed2a6abf7158809cf4f3c) <= 2 ** 127
    assert get_msb(0x000102030405060708090a0b0c0d0e0f) <= 2 ** 127
    assert get_msb(0x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b) <= 2 **191
    assert get_msb(0x000102030405060708090a0b0c0d0e0f1011121314151617) <= 2 **191
    assert get_msb(0x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4) <= 2 **255
    assert get_msb(0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f) <= 2 **255