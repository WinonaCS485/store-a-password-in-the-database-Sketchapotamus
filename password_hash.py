import hashlib, binascii, os

def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")
    password_hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000)
    password_hash = binascii.hexlify(password_hash)
    return (salt + password_hash).decode("ascii")

def check_password(password_hash, password):
    salt = password_hash[:64]
    password_hash = password_hash[64:]
    hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("ascii"), 10000)
    hash = binascii.hexlify(hash).decode("ascii")
    print(password_hash)
    print(hash)
    return password_hash == hash


def main():
    print("Enter password:", end=' ')
    password = input()
    passhash = hash_password(password)
    print("Check Password:", end=' ')
    check = input()
    if(check_password(passhash, check)):
        print("Access Granted")
    else:
        print("Hacker Detected")

    return


main()