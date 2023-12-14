import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes


def encrypt_file(key, iv, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = in_filename + '.enc'

    encryptor = AES.new(key, AES.MODE_CBC, iv)

    with open(in_filename, 'rb') as infile, open(out_filename, 'wb') as outfile:
        outfile.write(iv)  # Write the IV to the output file

        while True:
            chunk = infile.read(chunksize)
            if len(chunk) == 0:
                break
            elif len(chunk) % AES.block_size != 0:
                chunk = pad(chunk, AES.block_size)

            outfile.write(encryptor.encrypt(chunk))


def decrypt_file(key, in_filename, out_filename=None, chunksize=64*1024):
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    with open(in_filename, 'rb') as infile:
        iv = infile.read(AES.block_size)  # Read the IV from the input file
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(unpad(decryptor.decrypt(chunk), AES.block_size))


def generate_random_key():
    return token_bytes(16)  # AES-128


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python script.py encrypt/decrypt input_file output_file key_file")
        sys.exit(1)

    action, input_filename, output_filename, key_file = sys.argv[
        1], sys.argv[2], sys.argv[3], sys.argv[4]
    input_dir = "Inputs"
    output_dir = "Outputs"
    key_dir = "Keys"

    # Create directories if they don't exist
    os.makedirs(input_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(key_dir, exist_ok=True)

    in_path = os.path.join(input_dir, input_filename)
    out_path = os.path.join(output_dir, output_filename)
    key_path = os.path.join(key_dir, key_file)

    if action == "encrypt":
        key = generate_random_key()
        iv = token_bytes(AES.block_size)
        if not os.path.exists(in_path):
            print(f"Error: Input file '{in_path}' does not exist.")
            sys.exit(1)

        encrypt_file(key, iv, in_path, out_path)
        with open(key_path, 'wb') as keyfile:
            keyfile.write(key)
        print(
            f"File '{in_path}' encrypted and saved as '{out_path}'. Key saved to '{key_path}'.")

    elif action == "decrypt":
        if not os.path.exists(in_path) or not os.path.exists(key_path):
            print(
                f"Error: Input file '{in_path}' or key file '{key_path}' does not exist.")
            sys.exit(1)

        with open(key_path, 'rb') as keyfile:
            key = key_path.read()
        decrypt_file(key, in_path, out_path)
        print(f"File '{in_path}' decrypted and saved as '{out_path}'.")

    else:
        print("Usage: python script.py encrypt/decrypt input_file output_file key_file")
        sys.exit(1)
