import importlib
import optparse


def check_input():
    parser = optparse.OptionParser("%prog <alg> [-m <message>]")
    parser.add_option("-a", dest="alg", help="algorithm to encrypt the message with")
    parser.add_option("-m", "--msg", dest="msg", help="message to encrypt")
    (options, args) = parser.parse_args()

    if not options.alg:
        parser.print_help()
        exit(0)

    alg = importlib.import_module("core." + options.alg)
    msg = input("Message to encrypt: ") if not options.msg else options.msg

    return alg, msg


def main():
    alg, msg = check_input()

    if hasattr(alg, "encrypt"):
        cipher = alg.encrypt(msg)
        print("Cipher text: " + cipher)
    else:
        cipher = alg.hash_sum(msg)
        print("Hash: " + cipher)


if __name__ == "__main__":
    main()
