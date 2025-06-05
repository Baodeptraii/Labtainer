from server import Server

def print_blocks(data, label="Ciphertext"):
    print(f"\n🔸 {label} (len={len(data)}):")
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        print(f"  Block {i//16}: {block.hex()}")

def iv_demo():
    # Thông điệp cố định
    message = "This is a test message for IV demonstration!"
    print(f"Plaintext: {message}")

    # Key cố định
    key = "iv_demo_key_1234"
    server = Server(key)

    msg_bytes = message.encode()

    # IV 1: toàn 0
    iv1 = bytes.fromhex("00000000000000000000000000000000")
    cipher1 = server.httpRequestForEncryptedText(msg_bytes, iv1)
    print_blocks(cipher1, "Ciphertext with IV = 0x00...")

    # IV 2: toàn 0x11
    iv2 = bytes.fromhex("11111111111111111111111111111111")
    cipher2 = server.httpRequestForEncryptedText(msg_bytes, iv2)
    print_blocks(cipher2, "Ciphertext with IV = 0x11...")

    # IV random
    cipher3 = server.httpRequestForEncryptedText(msg_bytes)
    print_blocks(cipher3, "Ciphertext with random IV")

    # So sánh
    print("\nKết luận:")
    print("IV1 == IV2? ", cipher1 == cipher2)
    print("IV1 == Random? ", cipher1 == cipher3)

    if cipher1 != cipher2 and cipher1 != cipher3:
        print("Kết quả: \nMỗi IV tạo ciphertext hoàn toàn khác biệt.")
        print("Dù plaintext và key giống nhau, nhưng IV khác → ciphertext khác.")
        print("Điều này chứng tỏ IV là yếu tố quan trọng trong bảo mật của thuật toán mã hóa.")
        print("Nhưng BEAST lợi dụng TLS 1.0 và CBC mode, khiến IV có thể bị đoán được, dẫn đến dễ bị tấn công.")
    else:
        print("Có gì đó sai — ciphertext đang trùng nhau ?!")

if __name__ == "__main__":
    iv_demo()
