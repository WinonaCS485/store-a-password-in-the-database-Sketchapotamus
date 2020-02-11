import binascii
import hashlib
import os
import pymysql.cursors

connection = pymysql.connect(host='mrbartucz.com',
                                 user='zt9916nr',
                                 password='password',
                                 db='zt9916nr_users',
                                 charset='utf8mb4',
                                 cursorclass=pymysql.cursors.DictCursor)

sql_get_users = "SELECT * from UserLogin WHERE Username = %s"
sql_new_user = "INSERT INTO UserLogin (UserName, Salt, PasswordHash) VALUES (%s,%s,%s)"
sql_get_salt_hash = "SELECT Salt, PasswordHash from UserLogin WHERE Username = %s"


def hash_password(password):
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode("ascii")
    password_hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000)
    password_hash = binascii.hexlify(password_hash)
    return salt.decode("ascii"), password_hash.decode("ascii")


def check_password(salt, password_hash, password):

    hash = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("ascii"), 100000)
    hash = binascii.hexlify(hash).decode("ascii")
    return password_hash == hash


def new_user():
    print("Enter username:", end=' ')
    username = input()
    print("Enter password:", end=' ')
    pass1 = input()
    print("Re-enter password:", end=' ')
    pass2 = input()
    if pass1 == pass2:
        with connection.cursor() as cursor:
            cursor.execute(sql_get_users, username)
            if cursor.rowcount == 0:
                pass_hash = hash_password(pass1)
                user_salt_hash = (username, pass_hash[0], pass_hash[1])
                cursor.execute(sql_new_user, user_salt_hash)
                connection.commit()
                print("User account created.")
            else:
                print("Username is already in use.")


def login():
    print("Enter username:", end=' ')
    username = input()
    print("Enter password:", end=' ')
    user_pass = input()
    salt = None
    password_hash = None
    with connection.cursor() as cursor:

        cursor.execute(sql_get_salt_hash, username)
        row = cursor.fetchone()
        if row is not None:
            salt = row["Salt"]
            password_hash = row["PasswordHash"]
            if check_password(salt, password_hash, user_pass):
                print("Logged In!")
            else:
                print("Please check username and password.")


def main():
    print("1: Existing User\n2: New User\nPlease Select:", end=' ')
    user_input = input()

    if user_input == "1":
        login()

    if user_input == "2":
        new_user()
        print("\nPlease log in.")
        login()

    return


main()
