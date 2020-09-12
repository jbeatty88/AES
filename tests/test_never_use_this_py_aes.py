from never_use_this_py_aes import PyAES

aes = PyAES("plaintext message", "key")
aes_decrypt = PyAES("10e88c420358a84775422ca05677891f", "a38130d79493f583b6543e4e0e4b17c9")
aes_encrypt = PyAES("10e88c420358a84775422ca05677891f")


def test_can_get_message():
    assert aes.message == "plaintext message"
    assert aes_decrypt.message == "10e88c420358a84775422ca05677891f"
    assert aes_encrypt.message == "10e88c420358a84775422ca05677891f"


def test_can_get_key():
    assert aes.key == "key"
    assert aes_decrypt.key == "a38130d79493f583b6543e4e0e4b17c9"
    assert aes_encrypt.key == None


def test_mode_set_correctly():
    assert aes.mode == "decrypt"
    assert aes_decrypt.mode == "decrypt"
    assert aes_encrypt.mode == "encrypt"


def test_ff_add():
    assert hex(aes.ff_add(0x57, 0x83)) == hex(0xd4)


def test_xtime():
    assert hex(aes.xtime(0x57)) == hex(0xae)
    assert hex(aes.xtime(0xae)) == hex(0x47)
    assert hex(aes.xtime(0x47)) == hex(0x8e)
    assert hex(aes.xtime(0x8e)) == hex(0x07)


def test_make_xtime_table():
    assert False


def test_ff_multiply():
    assert hex(aes.ff_multiply(0x57, 0x13)) == hex(0xfe)
    assert hex(aes.ff_multiply(0x13, 0x57)) == hex(0xfe)
    assert hex(aes.ff_multiply(0x70, 0x27)) == hex(0xc9)
    assert hex(aes.ff_multiply(0x27, 0x70)) == hex(0xc9)
    assert hex(aes.ff_multiply(0x22, 0x0e)) == hex(0xc7)
    assert hex(aes.ff_multiply(0x0e, 0x22)) == hex(0xc7)


def test_sub_bytes():
    assert False


def test_shift_rows():
    assert False


def test_mix_column():
    assert False


def test_mix_columns():
    assert False


def test_add_round_key():
    assert False


def test_inv_sub_bytes():
    assert False


def test_inv_shift_rows():
    assert False


def test_inv_mix_column():
    assert False


def test_inv_mix_columns():
    assert False


def test_sub_word():
    assert False


def test_rot_word():
    assert False
