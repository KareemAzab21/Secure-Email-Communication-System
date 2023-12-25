from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Sender (Key Pair Generation)
sender_key = RSA.generate(2048)
sender_private_key = sender_key.export_key()
sender_public_key = sender_key.publickey().export_key()

# Save sender's private and public keys to files
with open('Signature_Keys/sender_private_key.pem', 'wb') as private_key_file:
    private_key_file.write(sender_private_key)

with open('Signature_Keys/sender_public_key.pem', 'wb') as public_key_file:
    public_key_file.write(sender_public_key)

# Sender (Signature Generation)


def sign_message(message, private_key_path):
    with open(private_key_path, 'rb') as private_key_file:
        private_key = RSA.import_key(private_key_file.read())
        h = SHA256.new(message.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)
        return signature


message_to_send = "This is a message from the sender"
signature = sign_message(
    message_to_send, 'Signature_Keys/sender_private_key.pem')

# Recipient (Signature Verification)


def verify_signature(message, signature, public_key_path):
    with open(public_key_path, 'rb') as public_key_file:
        public_key = RSA.import_key(public_key_file.read())
        h = SHA256.new(message.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(h, signature)
            return True  # Signature is valid
        except (ValueError, TypeError):
            return False  # Signature is invalid


# Simulate message transmission use case
# message_received = "This is a message from the sender"
# signature_received = signature

# if verify_signature(message_received, signature_received, 'Signature_Keys/sender_public_key.pem'):
#     print("Signature verification successful. Message is authentic.")
# else:
#     print("Signature verification failed. Message may be tampered.")
