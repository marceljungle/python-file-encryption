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
    counterRand = random.randint(10, 16)
    chunk_size = 64*1024
    output_file = "ENC"+filename
    file_size = str(os.path.getsize(filename)).zfill(16)
    IV = ''
    for i in range(16):  # PKCS7Padding ya que es de 16 bytes modificables, y no 8 bytes fijos como en PKCS5Padding
        IV += chr(random.randint(0, 0xF))
    begin_time = datetime.datetime.now()
    counter = Counter.new(128, initial_value=counterRand)
    #encryptor = AES.new(key, AES.MODE_GCM, IV.encode("utf8"))
    encryptor = AES.new(key, AES.MODE_CTR, counter=counter)
    with open(filename, 'rb') as inputfile:
        with open(output_file, 'wb') as outf:
            outf.write(file_size.encode("utf8"))
            # outf.write(IV.encode("utf8"))
            outf.write(str(counterRand).encode("utf8"))
            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += (' '*(16 - len(chunk) % 16)).encode("utf8")
                outf.write(encryptor.encrypt(chunk))
    end = datetime.datetime.now() - begin_time
    print("Ha tardado en encriptar: " + str(end))


def decrypt(key, filename):
    chunk_size = 64*1024
    output_file = "DEC" + filename[3:]
    begin_time = datetime.datetime.now()
    with open(filename, 'rb') as inf:
        filesize = int(inf.read(16))
        #IV = inf.read(16)
        IV = inf.read(2)
        counter = Counter.new(128, initial_value=int(IV.decode("utf8")))
        #decryptor = AES.new(key, AES.MODE_GCM, IV)
        decryptor = AES.new(key, AES.MODE_CTR, counter=counter)
        with open(output_file, 'wb') as outf:
            while True:
                chunk = inf.read(chunk_size)
                if len(chunk) == 0:
                    break
                outf.write(decryptor.decrypt(chunk))
            outf.truncate(filesize)
    end = datetime.datetime.now() - begin_time
    print("Ha tardado en decriptar: " + str(end))


def getKey(password):
    hasher = SHA256.new(password.encode("utf8"))
    return hasher.digest()


def main():
    choice = int()
    choice = input(
        "Select One of the following\n> 1. Encrypt \n> 2. Decrypt\n>> ")
    if choice == "1":
        filename = input("Enter the name of file to be encrypted >> ")
        password = input("Enter the password >> ")
        mode = input(
            "Choose what mode you want for encryption:\n1. AES-CBC\n2. AES-GCM\n3. AES-CTR")
        encrypt(getKey(password), filename, mode)
        print("Done!\n{} ==> {}".format(filename, "ENC" + filename))
    elif choice == "2":
        filename = input("File to be decrypted > ")
        password = input("Password: ")
        decrypt(getKey(password), filename)
        print("Done!\n{} ==> {}".format(filename, "DEC" + filename[3:]))
    else:
        print("No option Selected")


def hashGenerator():
    archivo = "tibia.png"
    archivoENC = "DECtibia.png"

    with open((archivo), "rb") as fileRaw1:
        result1 = hashlib.sha3_256(
            fileRaw1.read()).hexdigest()
    with open((archivo), "rb") as fileRaw2:
        result2 = hashlib.sha3_256(
            fileRaw2.read()).hexdigest()
    if(result1 == result2):
        print("\n\nComparando los hashes de los archivos " +
              archivo + " y " + archivoENC + ":")
        print("Los hashes  coinciden!")
        print("Archivo original: " + result2 + "\n" +
              "Archivo desencriptado: " + result1 + "\n\n")
    else:
        print("Los hashes no coinciden!")
        print("Archivo original: " + result2 + "\n" +
              "Archivo desencriptado: " + result1 + "\n\n")


if __name__ == "__main__":
    main()
    # hashGenerator()
