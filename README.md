# Password Cracker
A tool written in Python to crack MD4, MD5, SHA-1, SHA-256 or SHA-512 hashes using a defined character set.

# Syntax Guide
```console
root@pc:~# python password-cracker.py
```
```diff
-[+] Usage: python bruteforce.py <type of hash> <hash> <minimun length> <maximum length> <character set>
-[+] Example: python bruteforce.py md5 8c7dd922ad47494fc02c388e12c00eac 3 7 <ALPHA_LOWER>
-[+] Hashes supported: MD4, MD5, SHA-1, SHA-256, SHA-512


#[+] Character sets:
#        NUM:    0123456789
#        NUM_SPECIAL:    0123456789!@#$%^&*()-_+=~`[]\{\}\|:;'"<>,./?
#        ALPHA_CAPS:     ABCDEFGHIJKLMNOPQRSTUVWXYZ
#        ALPHA_LOWER:    abcdefghijklmnopqrstuvwxyz
#        ALPHA_CAPS_LOWER:       ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
#        ALPHA_CAPS_LOWER_NUM:   ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
#        ALPHA_LOWER_SPECIAL:    abcdefghijklmnopqrstuvwxyz!@#$%^&*()-_+=~`[]\{\}\|:;'"<>,./?  
#        ALPHA_CAPS_SPECIAL:     ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()-_+=~`[]\{\}\|:;'"<>,./?  
#        ALPHA_LOWER_NUM:        abcdefghijklmnopqrstuvwxyz0123456789
#        ALPHA_CAPS_NUM: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
#        ALPHA_CAPS_NUM_SEPCIAL: ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]\{\}\|:;'"<>,./?
#        ALL:    ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=~`[]\{\}\|:;'"<>,./?
```
![Example](/image.JPG)
