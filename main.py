# This is a sample Python script.
import sys
from never_use_this_py_aes import PyAES
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.

def main(argv):
    if len(argv) == 0:
        message = input("Please input message --> ")
        key = input("Please input key --> ")
        action = input("Encrypt or decrypt? ")
    else:
        message = argv[0]
        key = argv[1]
        action = argv[2]

    aes = PyAES(message, key)
    res = None
    if action.lower() == 'encrypt' or action.lower() == 'e':
        action = 'encrypt'
        print("----------------------------------------------------")
        print("Beginning {}ion of message: {}".format(action, message))
        print("----------------------------------------------------")
        res = aes.encrypt()
    elif action.lower() == 'decrypt' or action.lower() == 'd':
        action = 'decrypt'
        print("----------------------------------------------------")
        print("Beginning {}ion of message: {}".format(action, message))
        print("----------------------------------------------------")
        res = aes.decrypt()
    else:
        print("Usage: <PyProgram> <MSG> <KEY> <ENCRYPT | DECRYPT")

    print("Successfully {}ed message: {}".format(action, message))
    print("Result of {}ion: {}".format(action, res))
    print("----------------------------------------------------")

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(sys.argv[1:])

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
