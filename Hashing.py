import sys
import os
import hashlib


def hash_file(filename):
    """Generate SHA-256 hash of the given file."""
    sha256_hash = hashlib.sha256()

    with open(filename, 'rb') as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()


# # Testing the Hashing function
# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Usage: python script.py <filename>")
#         sys.exit(1)

#     filename = sys.argv[1]
#     input_dir = "Inputs"
#     os.makedirs(input_dir, exist_ok=True)
#     file_path = os.path.join(input_dir, filename)
#     hash_value = hash_file(file_path)
#     print(f"The SHA-256 hash of {file_path} is: {hash_value}")
