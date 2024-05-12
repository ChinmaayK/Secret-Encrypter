import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import gzip
from concurrent.futures import ThreadPoolExecutor
import sys


def gen_key(password, salt):
    password = password.encode()
    salt = salt.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # with open("thekey.key", "wb") as thekey:
    #     thekey.write(key)
    return key


def get_data_from_img(img_path):
    with open(img_path, "rb") as img:
        content = img.read()
        offset = content.index(bytes.fromhex('FFD9'))
        img.seek(offset + 2)
        encrypted_data = img.read()
        uncompressed_data = gzip.decompress(encrypted_data)
        return (base64.b64decode(uncompressed_data)).decode()
        # return content


def get_data_to_decrypt(data):
    data = data.split("'\n<-Separator->")
    filenames = []
    file_content = []
    for file_data in data:
        filename_start = file_data.find("filename=")
        filename_end = file_data.find("\n", filename_start)
        filename = file_data[filename_start + len("filename="): filename_end]
        contents = file_data[filename_end + 3:]
        filenames.append(filename)
        file_content.append(contents)
        # print(file_content)
    return filenames[:-1], file_content[:-1]


def decrypt_data(data, folder_location, filename, f):
    decrypted_data = f.decrypt(data)
    file_path = os.path.join(folder_location, filename)
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "wb") as file:
        file.write(decrypted_data)


def save_decrypt_to_file(filenames, file_content, folder_location, f):
    total_files = len(filenames)
    processed_files = 0
    if not os.path.exists(folder_location):
        os.makedirs(folder_location)
    with ThreadPoolExecutor(max_workers=10) as executor:
        try:
            results = executor.map(decrypt_data, file_content, [folder_location] * len(file_content), filenames, [f] * len(file_content))

            for _ in results:
                processed_files += 1
                progress = (processed_files / total_files) * 100
                sys.stdout.write(f"\rProgress: [{int(progress)}%]")
                sys.stdout.flush()

        except Exception as e:
            print(f"error in {e}")


def main(img, folder, f):
    print("Getting data from image")
    retrieved_data = get_data_from_img(img)
    print("Organising data")
    filenames, file_content = get_data_to_decrypt(retrieved_data)
    print("Saving data")
    save_decrypt_to_file(filenames, file_content, folder, f)

