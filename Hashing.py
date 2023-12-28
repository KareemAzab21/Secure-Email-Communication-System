import sys
import os
import hashlib


def hash_content(content):
    """Generate SHA-256 hash of the given content."""
    sha256_hash = hashlib.sha256()

    if isinstance(content, str):
        # If content is a string, encode it to bytes
        content = content.encode('utf-8')

    sha256_hash.update(content)

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
