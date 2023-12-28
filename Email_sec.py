import win32com.client
import os
import tempfile
from Encrypt_Decrypt import *
from Hashing import *
from Signature import *


def send_secure_email(to, subject, body, attachment_path, private_key_path):
    outlook_app = win32com.client.Dispatch("Outlook.Application")
    mail_item = outlook_app.CreateItem(0)  # 0 represents olMailItem constant
    mail_item.To = to
    mail_item.Subject = subject
    mail_item.Body = body

    # Read the attachment and encrypt it
    with open(attachment_path, 'rb') as f:
        attachment_content = f.read()

    # Encryption
    key = generate_random_key()
    iv = token_bytes(AES.block_size)
    encrypted_content = encrypt_content(key, iv, attachment_content)

    # Save encrypted content to a temporary file
    encrypted_attachment_path = os.path.join(
        tempfile.gettempdir(), 'encrypted_attachment.enc')
    with open(encrypted_attachment_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_content)

    # Hashing
    hash_value = hash_content(encrypted_content)
    hash_attachment_path = os.path.join(
        tempfile.gettempdir(), 'content_hash.txt')
    with open(hash_attachment_path, 'w') as hash_file:
        hash_file.write(hash_value)

    # Signing
    signature = sign_message(hash_value, private_key_path)
    signature_attachment_path = os.path.join(
        tempfile.gettempdir(), 'signature.sig')
    with open(signature_attachment_path, 'wb') as signature_file:
        signature_file.write(signature)

    # Save the encryption key and IV to a temporary file - NOT RECOMMENDED FOR ACTUAL USE!
    # You should encrypt this key file with the recipient's public key in a real application.
    key_iv_path = os.path.join(tempfile.gettempdir(), 'key_iv.txt')
    with open(key_iv_path, 'w') as key_iv_file:
        key_iv_file.write(f'{key.hex()}|{iv.hex()}')

    # Attaching files to the email
    mail_item.Attachments.Add(encrypted_attachment_path)
    mail_item.Attachments.Add(hash_attachment_path)
    mail_item.Attachments.Add(signature_attachment_path)
    mail_item.Attachments.Add(key_iv_path)  # Attach the key and IV file

    # Send the email
    mail_item.Send()

    # Clean up temporary files
    os.remove(encrypted_attachment_path)
    os.remove(hash_attachment_path)
    os.remove(signature_attachment_path)
    os.remove(key_iv_path)  # Remove the key and IV file


def read_secure_email(public_key_path):
    outlook_app = win32com.client.Dispatch("Outlook.Application")
    namespace = outlook_app.GetNamespace("MAPI")
    inbox = namespace.GetDefaultFolder(6)  # 6 is the folder number for Inbox
    messages = inbox.Items

    for message in messages:
        if "Secure Email" in message.Subject:  # Filter for secure emails
            encrypted_attachment_path = None
            hash_attachment_path = None
            signature_attachment_path = None
            key_iv_attachment_path = None

            for attachment in message.Attachments:
                temp_path = os.path.join(
                    tempfile.gettempdir(), attachment.FileName)
                attachment.SaveAsFile(temp_path)

                if attachment.FileName.endswith('.enc'):
                    encrypted_attachment_path = temp_path
                elif attachment.FileName.endswith('content_hash.txt'):
                    hash_attachment_path = temp_path
                elif attachment.FileName.endswith('signature.sig'):
                    signature_attachment_path = temp_path
                elif attachment.FileName.endswith('key_iv.txt'):
                    key_iv_attachment_path = temp_path

            if all([encrypted_attachment_path, hash_attachment_path, signature_attachment_path, key_iv_attachment_path]):
                with open(encrypted_attachment_path, 'rb') as encrypted_file:
                    encrypted_content = encrypted_file.read()
                with open(hash_attachment_path, 'r') as hash_file:
                    original_hash = hash_file.read().strip()
                with open(signature_attachment_path, 'rb') as signature_file:
                    signature = signature_file.read()
                with open(key_iv_attachment_path, 'r') as key_iv_file:
                    key_hex, iv_hex = key_iv_file.read().split('|')
                    key = bytes.fromhex(key_hex)
                    iv = bytes.fromhex(iv_hex)

                if verify_signature(original_hash, signature, public_key_path):
                    print("Signature verified.")

                    decrypted_content = decrypt_content(
                        key, iv, encrypted_content)
                    print("Decrypted Content:",
                          decrypted_content.decode('utf-8'))
                else:
                    print("Signature verification failed.")

                # Clean up temporary files
                os.remove(encrypted_attachment_path)
                os.remove(hash_attachment_path)
                os.remove(signature_attachment_path)
                os.remove(key_iv_attachment_path)


# send_secure_email(
#     to="19p5097@eng.asu.edu.eg",
#     subject="Secure Email",
#     body="Hello This is a plain text  Email, Please check the attachements ",
#     # Just the file name is needed, not the full path
#     attachment_path="attachment.txt",
#     private_key_path='Signature_Keys/sender_private_key.pem'
# )


read_secure_email(
    public_key_path='Signature_Keys/sender_public_key.pem'

)
