
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import shutil
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


def get_ignore_locations(ignore_loc):
    ignore_locations = []
    if ignore_loc is not None:
        try:
            with open(ignore_loc, 'r') as file:
                for line in file:
                    ignore_locations.append(line.strip())
        except FileNotFoundError:
            print("loc.txt not found. No locations will be ignored.")
    return ignore_locations


def get_files(directory, ignore_loc):
    ignore_locations = get_ignore_locations(ignore_loc)
    files = []
    for item in os.listdir(directory):
        full_path = os.path.join(directory, item)

        # Check if the full_path is in the ignore_locations list
        if full_path in ignore_locations:
            continue

        if os.path.isfile(full_path):
            files.append(full_path)
        elif os.path.isdir(full_path):
            files.extend(get_files(full_path, ignore_loc))

    return files


def encrypt_file(file, folder, key):
    with open(file, "rb") as thefile:
        contents = thefile.read()
    encrypted_data = Fernet(key).encrypt(contents)
    file_data = f"filename={os.path.relpath(file, folder)}\n{encrypted_data}\n<-Separator->"
    return file_data


def get_encrypted_data(folder, files, key):
    encrypted_content = ""
    total_files = len(files)
    processed_files = 0
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(encrypt_file, files, [folder] * len(files), [key] * len(files))  # Pass 'key' to 'encrypt_file'

    for file_data in results:
        encrypted_content += file_data
        processed_files += 1
        progress = (processed_files / total_files) * 100
        sys.stdout.write(f"\rProgress: [{int(progress)}%]")
        sys.stdout.flush()
    return encrypted_content


def main(img, files_folder, output_img, ignore_loc, key):
    files = get_files(files_folder, ignore_loc)
    encrypted_data = get_encrypted_data(files_folder, files, key)
    base64_data = base64.b64encode(encrypted_data.encode())
    print("\nConverted to Base64 encoding")
    compressed_data = gzip.compress(base64_data)
    print("Compressed data")

    shutil.copy(img, output_img)
    with open(output_img, "ab") as img:
        img.write(compressed_data)
