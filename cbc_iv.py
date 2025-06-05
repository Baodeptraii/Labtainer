from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16

def fix_key(key_raw):
    if len(key_raw) < 16:
        return key_raw.ljust(16, b'\x00')
    elif 16 <= len(key_raw) < 24:
        return key_raw.ljust(24, b'\x00')
    elif 24 <= len(key_raw) < 32:
        return key_raw.ljust(32, b'\x00')
    else:
        return key_raw[:32]

def encrypt_tls_with_random_iv_per_record(records, key):
    all_ciphertext = []

    for i, record in enumerate(records):
        iv = get_random_bytes(BLOCK_SIZE)  # IV riêng cho từng bản ghi
        padded = pad(record, BLOCK_SIZE)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded)

        print(f"\n🔹 TLS Record {i+1}")
        print(f"Random IV     : {iv.hex()}")
        print(f"Plaintext     : {record}")
        print(f"Ciphertext    : {ciphertext.hex()}")

        all_ciphertext.append(iv + ciphertext)

    return b"".join(all_ciphertext)

def split_into_tls_records(data, record_size):
    return [data[i:i+record_size] for i in range(0, len(data), record_size)]

def demo():
    try:
        with open("alice_message.txt", "rb") as f:
            lines = f.readlines()
            if len(lines) < 2:
                print("File phải có ít nhất hai dòng: dòng 1 là plaintext, dòng 2 là key.")
                return

            plaintext = lines[0].strip()
            raw_key = lines[1].strip()
            key = fix_key(raw_key)

        records = split_into_tls_records(plaintext, 32)

        print(f"Original message from file:\n{plaintext.decode(errors='ignore')}")
        encrypt_tls_with_random_iv_per_record(records, key)

    except FileNotFoundError:
        print("Không tìm thấy file alice_message.txt")

if __name__ == "__main__":
    demo()
