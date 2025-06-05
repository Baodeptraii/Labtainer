msg = input("Enter a message to send to Alice: (atleast 8 bytes) ")
key = input("Enter a key to use for encryption: (atleast 8 bytes) ")

# Sinh ra file
with open("alice_message.txt", "w") as f:
    f.write(f"{msg}\n")
    f.write(f"{key}\n")