from never_use_this_py_aes import PyAES

aes = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f")
aes_128_e = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f")
aes_128_d = PyAES("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f")
aes_192 = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617")
aes_256 = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
aes_128_byu = PyAES("193de3bea0f4e22b9ac68d2ae9f84808", "3243f6a8885a308d313198a2e0370734")
aes_appendix_a = PyAES("2b7e151628aed2a6abf7158809cf4f3c", "2b7e151628aed2a6abf7158809cf4f3c")
aes_appendix_b = PyAES("3243f6a8885a308d313198a2e0370734", "2b7e151628aed2a6abf7158809cf4f3c")
aes_appendix_c_128_e = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f")
aes_appendix_c_128_d = PyAES("69c4e0d86a7b0430d8cdb78070b4c55a", "000102030405060708090a0b0c0d0e0f")
aes_appendix_c_192_e = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f1011121314151617")
aes_appendix_c_128_e = PyAES("00112233445566778899aabbccddeeff", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")


def test_can_get_message():
    assert aes_128_e.message == "00112233445566778899aabbccddeeff"
    assert aes_256.message == "00112233445566778899aabbccddeeff"
    assert aes_128_d.message == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes_192.message == "00112233445566778899aabbccddeeff"
    assert aes_256.message == "00112233445566778899aabbccddeeff"
    assert aes_128_byu.message == "193de3bea0f4e22b9ac68d2ae9f84808"
    assert aes_appendix_a.message == "2b7e151628aed2a6abf7158809cf4f3c"
    assert aes_appendix_b.message == "3243f6a8885a308d313198a2e0370734"

def test_can_get_key():
    assert aes_128_e.key == "000102030405060708090a0b0c0d0e0f"


def test_ff_add():
    assert hex(aes.ff_add(0x57, 0x83)) == hex(0xd4)


def test_xtime():
    assert hex(aes.xtime(0x57)) == hex(0xae)
    assert hex(aes.xtime(0xae)) == hex(0x47)
    assert hex(aes.xtime(0x47)) == hex(0x8e)
    assert hex(aes.xtime(0x8e)) == hex(0x07)


def test_ff_multiply():
    assert hex(aes.ff_multiply(0x57, 0x13)) == hex(0xfe)
    assert hex(aes.ff_multiply(0x13, 0x57)) == hex(0xfe)
    assert hex(aes.ff_multiply(0x70, 0x27)) == hex(0xc9)
    assert hex(aes.ff_multiply(0x27, 0x70)) == hex(0xc9)
    assert hex(aes.ff_multiply(0x22, 0x0e)) == hex(0xc7)
    assert hex(aes.ff_multiply(0x0e, 0x22)) == hex(0xc7)

byu_128_test_state = aes_128_byu.convert_message_to_state_array()
byu_128_test_key = aes_128_byu.convert_key_to_byte_array()

def test_sub_bytes():
    assert aes_128_e.sub_bytes(
        [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]) \
           == [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]

    assert aes_128_byu.sub_bytes(byu_128_test_state) == [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]


def test_shift_rows():
    assert aes_128_e.shift_rows(
        [0xd4, 0x27, 0x11, 0xae, 0xe0, 0xbf, 0x98, 0xf1, 0xb8, 0xb4, 0x5d, 0xe5, 0x1e, 0x41, 0x52, 0x30]) \
           == [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]


def test_mix_columns():
    assert aes_128_e.mix_columns(
        [0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae, 0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5]) \
           == [0x04, 0x66, 0x81, 0xe5, 0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c]


def test_add_round_key():
    assert aes_appendix_b.add_round_key(aes_appendix_b.state_1d_byte_array, aes_appendix_b.key_1d_byte_array) == \
           [0x19, 0x3d, 0xe3, 0xbe, 0xa0, 0xf4, 0xe2, 0x2b, 0x9a, 0xc6, 0x8d, 0x2a, 0xe9, 0xf8, 0x48, 0x08]
    # assert aes_128.add_round_key([0x04, 0x66, 0x81, 0xe5,0xe0, 0xcb, 0x19, 0x9a, 0x48, 0xf8, 0xd3, 0x7a, 0x28, 0x06, 0x26, 0x4c ])\
    # == [0xa4, 0x9c, 0x7f, 0xf2, 0x68, 0x9f, 0x35, 0x2b, 0x6b, 0x5b, 0xea, 0x43, 0x02, 0x6a, 0x50, 0x49]


def test_get_rcon_value():
    assert aes.get_rcon_value(1) == 0x01
    assert aes.get_rcon_value(4) == 0x08
    assert aes.get_rcon_value(10) == 0x36
    assert aes.get_rcon_value(24) == 0xd4
    assert aes.get_rcon_value(45) == 0x83
    assert aes.get_rcon_value(3) == 0x04


def test_sub_word():
    assert aes.sub_word(0xcf) == 0x8a
    assert aes.sub_word(0x30) == 0x04
    assert aes.sub_word(0x50) == 0x53
    assert aes.sub_word(0xa0) == 0xe0


def test_rot_word():
    assert aes.rot_word([0x09, 0xcf, 0x4f, 0x3c]) == [0xcf, 0x4f, 0x3c, 0x09]
    assert aes.rot_word([0x2a, 0x6c, 0x76, 0x05]) == [0x6c, 0x76, 0x05, 0x2a]


def test_get_key_length_dependent_vars():
    assert aes_128_e.get_key_length_dependent_vars() == (4, 10)
    assert aes_192.get_key_length_dependent_vars() == (6, 12)
    assert aes_256.get_key_length_dependent_vars() == (8, 14)


def test_convert_key_to_byte_array():
    assert aes_128_e.convert_key_to_byte_array() == [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                     0x0b, 0x0c, 0x0d, 0x0e, 0x0f]


def test_convert_message_to_state_array():
    assert aes_128_e.convert_message_to_state_array() == [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                                                          0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]

def test_key_expansion():
    assert aes_appendix_a.key_expansion() == \
                         [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
                          0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05,
                          0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f,
                          0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b,
                          0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00,
                          0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc,
                          0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd,
                          0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f,
                          0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f,
                          0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e,
                          0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6 ]


def test_cipher():
    # assert aes_128_byu.cipher() == [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 ]
    assert aes_appendix_b.cipher() == [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32 ]

def test_inv_sub_bytes():
    assert aes_appendix_c_128_d.inv_sub_bytes([122, 159, 16, 39, 137, 213, 245, 11, 43, 239, 253, 159, 61, 202, 78, 167]) ==\
        [189, 110, 124, 61, 242, 181, 119, 158, 11, 97, 33, 110, 139, 16, 182, 137]


def test_inv_shift_rows():
    assert aes_appendix_c_128_d.inv_shift_rows([0x7a, 0xd5, 0xfd, 0xa7, 0x89, 0xef, 0x4e, 0x27, 0x2b, 0xca, 0x10, 0x0b, 0x3d, 0x9f, 0xf5, 0x9f]) == \
           [122, 159, 16, 39, 137, 213, 245, 11, 43, 239, 253, 159, 61, 202, 78, 167]


def test_inv_mix_columns():
    assert aes_appendix_c_128_d.inv_mix_columns([122, 159, 16, 39, 137, 213, 245, 11, 43, 239, 253, 159, 61, 202, 78, 167]) == \
           [0, 84, 213, 83, 31, 5, 60, 132, 44, 241, 173, 214, 241, 152, 190, 201]


def test_inv_cipher():
    assert aes_128_d.decrypt() == "00112233445566778899aabbccddeeff"