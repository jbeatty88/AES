from utils import ArithmeticUtils
u = ArithmeticUtils()
def test_extended_euclid():
    x, y, d = u.extended_euclid(25, 11)
    print("{} = gcd(a, b) and a*{} + b*{} = {}".format(d, x, y, d))
