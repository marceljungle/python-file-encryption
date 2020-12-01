#!/usr/bin/python3

import os
import random
import hashlib
import datetime
import sys
import random

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import pad
from Cryptodome.Util import Counter


def encrypt(key, filename, mode):
    chunk_size = 64*1024
    output_file = "ENC"+filename
    file_size = str(os.path.getsize(filename)).zfill(16)
    begin_time = datetime.datetime.now()
    if(mode == '3'):  # aes-ctr
        print("You choosed AES-CTR\n")
        counterRand = random.randint(10, 16)
        counter = Counter.new(128, initial_value=counterRand)
        encryptor = AES.new(key, AES.MODE_CTR, counter=counter)
        with open(filename, 'rb') as inputfile:
            with open(output_file, 'wb') as outf:
                outf.write(file_size.encode("utf8"))
                outf.write(str(counterRand).encode("utf8"))
                while True:
                    chunk = inputfile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += (' '*(16 - len(chunk) % 16)).encode("utf8")
                    outf.write(encryptor.encrypt(chunk))
    if(mode == '2'):  # aes-gcm
        print("You choosed AES-GCM\n")
        IV = ''
        # Its PKCS7Padding because it has 16 bytes and not 8 like PKCS5Padding
        for i in range(16):
            IV += chr(random.randint(0, 0xF))
        encryptor = AES.new(key, AES.MODE_GCM, IV.encode("utf8"))
        with open(filename, 'rb') as inputfile:
            with open(output_file, 'wb') as outf:
                outf.write(file_size.encode("utf8"))
                outf.write(IV.encode("utf8"))
                while True:
                    chunk = inputfile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += (' '*(16 - len(chunk) % 16)).encode("utf8")
                    outf.write(encryptor.encrypt(chunk))
    if(mode == '1'):  # aes-cbc
        print("You choosed AES-CBC\n")
        IV = ''
        # Its PKCS7Padding because it has 16 bytes and not 8 like PKCS5Padding
        for i in range(16):
            IV += chr(random.randint(0, 0xF))
        encryptor = AES.new(key, AES.MODE_CBC, IV.encode("utf8"))
        with open(filename, 'rb') as inputfile:
            with open(output_file, 'wb') as outf:
                outf.write(file_size.encode("utf8"))
                outf.write(IV.encode("utf8"))
                while True:
                    chunk = inputfile.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    elif len(chunk) % 16 != 0:
                        chunk += (' '*(16 - len(chunk) % 16)).encode("utf8")
                    outf.write(encryptor.encrypt(chunk))
    end = datetime.datetime.now() - begin_time
    print("It has taken: " + str(end) + " to ecrypt.")


def decrypt(key, filename, mode):
    chunk_size = 64*1024
    output_file = "DEC" + filename[3:]
    begin_time = datetime.datetime.now()

    if(mode == '3'):  # aes-ctr
        print("You choosed AES-CTR\n")
        with open(filename, 'rb') as inf:
            filesize = int(inf.read(16))
            IV = inf.read(2)
            counter = Counter.new(128, initial_value=int(IV.decode("utf8")))
            decryptor = AES.new(key, AES.MODE_CTR, counter=counter)
            with open(output_file, 'wb') as outf:
                while True:
                    chunk = inf.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    outf.write(decryptor.decrypt(chunk))
                outf.truncate(filesize)

    if(mode == '2'):  # aes-gcm
        print("You choosed AES-GCM\n")
        with open(filename, 'rb') as inf:
            filesize = int(inf.read(16))
            IV = inf.read(16)
            decryptor = AES.new(key, AES.MODE_GCM, IV)
            with open(output_file, 'wb') as outf:
                while True:
                    chunk = inf.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    outf.write(decryptor.decrypt(chunk))
                outf.truncate(filesize)

    if (mode == '1'):  # aes-cbc
        print("You choosed AES-CBC\n")
        with open(filename, 'rb') as inf:
            filesize = int(inf.read(16))
            IV = inf.read(16)
            decryptor = AES.new(key, AES.MODE_CBC, IV)
            with open(output_file, 'wb') as outf:
                while True:
                    chunk = inf.read(chunk_size)
                    if len(chunk) == 0:
                        break
                    outf.write(decryptor.decrypt(chunk))
                outf.truncate(filesize)
    end = datetime.datetime.now() - begin_time
    print("It has taken: " + str(end) + " to decrypt.")


def getKey(password):
    hasher = SHA256.new(password.encode("utf8"))
    return hasher.digest()


def main():
    choice = int()
    choice = input(
        "Select One of the following\n> 1. Encrypt \n> 2. Decrypt\n> 3. Integrity Check\n>> ")
    if choice == "1":
        filename = input("Enter the name of file to be encrypted >> ")
        password = input("Enter the password >> ")
        mode = input(
            "Choose what mode you want for encryption:\n1. AES-CBC\n2. AES-GCM\n3. AES-CTR\n>> ")
        encrypt(getKey(password), filename, mode)
        print("Done!\n{} ==> {}".format(filename, "ENC" + filename))
    elif choice == "2":
        filename = input("File to be decrypted > ")
        password = input("Password: ")
        mode = input(
            "Choose what mode you want for decryption:\n1. AES-CBC\n2. AES-GCM\n3. AES-CTR\n>> ")
        decrypt(getKey(password), filename, mode)
        print("Done!\n{} ==> {}".format(filename, "DEC" + filename[3:]))
    elif choice == "3":
        filenameFirst = input("First file to compare with a second one > ")
        filenameSecond = input("Second file to compare with the first one > ")
        hashChecker(filenameFirst, filenameSecond)  # order doesn't matter

    else:
        print("No option Selected")


def hashChecker(file1, file2):
    archivo = file1
    archivoENC = file2

    with open((archivo), "rb") as fileRaw1:
        result1 = hashlib.sha3_256(
            fileRaw1.read()).hexdigest()
    with open((archivoENC), "rb") as fileRaw2:
        result2 = hashlib.sha3_256(
            fileRaw2.read()).hexdigest()
    print("\n\nComparing both files... " +
          archivo + " and " + archivoENC + ":")
    if(result1 == result2):
        print("Both hashes match!")
        print("Second file: " + result2 + "\n" +
              "First file: " + result1 + "\n\n")
    else:
        print("Hashes doesn't match!")
        print("Second file: " + result2 + "\n" +
              "First file: " + result1 + "\n\n")


if __name__ == "__main__":
    main()
