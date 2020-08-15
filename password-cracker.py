import sys
import platform
import os
import hashlib
import re
from colorama import Fore, Style, Back
import itertools

HASH_LIST = (
    "md4",
    "md5",
    "sha1",
    "sha256",
    "sha512"
)

CHAR_SET = (
    "NUM",
    "NUM_SPECIAL",
    "ALPHA_CAPS",
    "ALPHA_LOWER",
    "ALPHA_CAPS_LOWER",
    "ALPHA_CAPS_LOWER_NUM",
    "ALPHA_LOWER_SPECIAL",
    "ALPHA_CAPS_SPECIAL",
    "ALPHA_LOWER_NUM",
    "ALPHA_CAPS_NUM",
    "ALPHA_CAPS_NUM_SEPCIAL",
    "ALL"
)

NUM = "0123456789"
NUM_SPECIAL = "0123456789!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "
ALPHA_CAPS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHA_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHA_CAPS_LOWER = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALPHA_CAPS_LOWER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
ALPHA_CAPS_SPECIAL ="ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "
ALPHA_LOWER_SPECIAL = "abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "
ALPHA_LOWER_NUM = "abcdefghijklmnopqrstuvwxyz0123456789"
ALPHA_CAPS_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHA_CAPS_NUM_SEPCIAL ="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "
ALPHA_LOWER_NUM_SEPCIAL = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "
ALL ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=~`[]\{\}\\|:;'\"<>,./? "

MD4_MD5_REGEX = re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE)
SHA_1_REGEX = re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE)
SHA_256_REGEX = re.compile(r"^[a-f0-9]{64}(:.+)?$", re.IGNORECASE)
SHA_512_REGEX = re.compile(r"^[a-f0-9]{128}(:.+)?$", re.IGNORECASE)

def usage():
    print(Fore.RED + "[+] Usage: python3 {} <type of hash> <hash> <minimun length> <maximum length> <character set>\n"
        "[+] Example: python3 {} md5 8c7dd922ad47494fc02c388e12c00eac 3 7 <ALPHA_LOWER>\n"
        "[+] Hashes supported: MD4, MD5, SHA-1, SHA-256, SHA-512"
        .format(sys.argv[0], sys.argv[0]))
    print(Style.RESET_ALL)
    print(
        "[+] Character sets:\n"
        "\tNUM:\t{}\n"
        "\tNUM_SPECIAL:\t{}\n"
        "\tALPHA_CAPS:\t{}\n"
        "\tALPHA_LOWER:\t{}\n"
        "\tALPHA_CAPS_LOWER:\t{}\n"
        "\tALPHA_CAPS_LOWER_NUM:\t{}\n"
        "\tALPHA_LOWER_SPECIAL:\t{}\n"
        "\tALPHA_CAPS_SPECIAL:\t{}\n"
        "\tALPHA_LOWER_NUM:\t{}\n"
        "\tALPHA_CAPS_NUM:\t{}\n"
        "\tALPHA_CAPS_NUM_SEPCIAL:\t{}\n"
        "\tALL:\t{}\n"
        .format(NUM, NUM_SPECIAL, ALPHA_CAPS, ALPHA_LOWER,
            ALPHA_CAPS_LOWER, ALPHA_CAPS_LOWER_NUM, ALPHA_LOWER_SPECIAL, ALPHA_CAPS_SPECIAL,
            ALPHA_LOWER_NUM, ALPHA_CAPS_NUM, ALPHA_CAPS_NUM_SEPCIAL, ALL)
    )


def banner():
    
    print(
        "__________                                               .___\n"
        "\______   \_____    ______ ________  _  _____________  __| _/\n"
        "|     ___/\__  \  /  ___//  ___/\ \/ \/ /  _ \_  __ \/ __ | \n"
        "|    |     / __ \_\___ \ \___ \  \     (  <_> )  | \/ /_/ | \n"
        "|____|    (____  /____  >____  >  \/\_/ \____/|__|  \____ | \n"
        "                \/     \/     \/                          \/ \n"
        "_________                       __                           \n"
        "\_   ___ \____________    ____ |  | __ ___________           \n"
        "/    \  \/\_  __ \__  \ _/ ___\|  |/ // __ \_  __ \          \n"
        "\     \____|  | \// __ \\  \___|    <\  ___/|  | \/          \n"
        " \______  /|__|  (____  /\___  >__|_ \\___  >__|             \n"
        "        \/            \/     \/     \/    \/    "
    )

def clear_scr():
    if platform.system() == "Windows":
        os.system("cls")
    elif platform.system() == "Linux":
        os.system("clear")

def success_print_result(passwd, h, r):
    if r == h:
        print(Fore.GREEN + "Hash: {}\tPassword: {}".format(h, passwd))
        print(Style.RESET_ALL)
        print("="*80)
        sys.exit()

def failed():
    print(Fore.RED + "[+] INVALID {} HASH".format(sys.argv[1]))
    print(Style.RESET_ALL)
    sys.exit()

def check_hash_type():
    if sys.argv[1] == HASH_LIST[0] or sys.argv[1] == HASH_LIST[1]:
        # Check if the hash is MD4 or MD5
        if not re.match(MD4_MD5_REGEX, sys.argv[2].lower()):
           failed() 
    elif sys.argv[1] == HASH_LIST[2]:
        # Check if the hash is SHA-1
        if not re.match(SHA_1_REGEX, sys.argv[2].lower()):
            failed()
    elif sys.argv[1] == HASH_LIST[3]:
        # Check if the hash is SHA-256
        if not re.match(SHA_256_REGEX, sys.argv[2].lower()):
            failed()
    elif sys.argv[1] == HASH_LIST[4]:
        # Check if the hash is SHA-512
        if not re.match(SHA_512_REGEX, sys.argv[2].lower()):
            failed()


def possible_combinations(iterate_over):
    c = list(iterate_over)
    return itertools.chain.from_iterable(itertools.product(c, repeat=r) for r in range(int(sys.argv[3]),int(sys.argv[4]) + 1))

def list_to_str(l):
    s = ''.join(l)
    return(s)

def main():
    if not sys.argv[1] in HASH_LIST:
        sys.exit(usage())
    if len(sys.argv) != 6:
        sys.exit(usage())
    if not sys.argv[5] in CHAR_SET:
        sys.exit(usage())
    clear_scr()
    banner()
    check_hash_type()
    print("="*80)
    for i in possible_combinations(sys.argv[5]):
        f = list_to_str(i)
        if sys.argv[1] == "md5":
            result = hashlib.md5(f.encode('utf-8')).hexdigest()
            success_print_result(f, sys.argv[2], result)
        elif sys.argv[1] == "sha1":
            result = hashlib.sha1(f.encode('utf-8')).hexdigest()
            success_print_result(f, sys.argv[2], result)
        elif sys.argv[1] == "sha256":
            result = hashlib.sha256(f.encode('utf-8')).hexdigest()
            success_print_result(f, sys.argv[2], result)
        elif sys.argv[1] == "sha512":
            success_print_result(f, sys.argv[2], result)
    print(Fore.RED + "No match was found")
    print(Style.RESET_ALL)


if __name__ == "__main__":
    main()
