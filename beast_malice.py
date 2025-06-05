from alice import Alice

class BEAST:
        
    def __str__(self) -> str:
        return "I am Malice, who exploits Alice for BEAST attack 😈"
    
    def _xor_strings(self, str1, str2, str3):
        """Helper function to perform xor between 3 byte strings. (Must be bytes datatype)

        Returns:
            bytes: xored value
        """
        # Check if the input strings have the same length
        # print(str1, str2, str3, len(str1), len(str2), len(str3))
        if len(str1) != len(str2) or len(str1) != len(str3):
            print("Can't perform BEAST Attack")
            print("You are using MODE_GCM, so the XOR operation is not possible. Please use MODE_CBC instead.")
            exit()

        print("[xor] str1: ", str1, type(str1), len(str1))
        print("[xor] str2: ", str2, type(str2), len(str2))
        print("[xor] str3: ", str3, type(str3), len(str3))
        
        result = bytes(x ^ y ^ z for x, y, z in zip(str1, str2, str3))

        return result
    
    def beast_attack(self):

        
        print("BEAST Attack in progress...")
        # chose target: Alice
        self._alice = Alice()
        print("new Alice chosen...")
        plaintext = ""
        known_prefix = ""
        

        # Pad the known prefix to align with block boundary
        padding = 16 - len(known_prefix) % 16
        known_prefix = "a" * padding + known_prefix

        # Iterate through the ciphertext blocks and perform the BEAST attack
        while len(plaintext) < self._alice.msgLength:
            # send request to calculate ciphertext with known prefix, with 1 byte from original plaintext
            # let, the known prefix is "aaaaaaaaaaaaaaa"(15 bytes). So, the second block of the ciphertext will be a cipher of known_prefix + 1 byte of actual plaintext
            # print("knownout: ", known_prefix)
            ciphertext = self._alice.forceRequestandIntercept(known_prefix[1:], len(plaintext))
            # prev_cipher = 1st block of ciphertext (previous iv)
            prev_cipher = ciphertext[:16]
            # target block = 2nd block of ciphertext (known_prefix + 1byte of pt)
            target_block = ciphertext[16:32]
            # iv = last block of ciphertext, which will be iv for next encryption
            iv = ciphertext[-16:]
            
            # that ciphertext's last block will be new iv, it's first block will be previous ciphertext, and guess will be
            for guess in range(256):
                # guess char = character we'll append (1 byte)
                guess_char = chr(guess)
                # modified_block = known_prefix (15 bytes) + guess (1 byte)
                modified_block = known_prefix[1:] + guess_char
                # xoredblock = xor these 3 so that iv cancels out, and prev_cipher and modified block creates the new ciphertext, that we're gonna check
                xoredblock = self._xor_strings(iv, prev_cipher, modified_block.encode())
                # modified_ciphertext = 1st block(16 byte) is IV, and next blocks are ciphers of the xoredblock
                modified_ciphertext = self._alice.forceRequestandIntercept(xoredblock, -1, iv)
                # print(ciphertext, "->", modified_ciphertext)
                if modified_ciphertext[16:32] == target_block:
                    known_prefix = known_prefix[1:] + guess_char
                    plaintext += guess_char
                    print("matched -> ", chr(guess), ", cracked: ", plaintext)
                    print("Found char: '{}'".format(guess_char))
                    print("new known: ", known_prefix)
                    input("ok?")
                    break
                elif guess == 255:
                    print("Unable to find the char...")
                    return plaintext

        return plaintext

malice = BEAST()
print(malice)
do = True
while do:
    decision = input("Perform BEAST on target Alice? (y/n): ")
    if(decision == "y"):
        crackedMsg = malice.beast_attack()
        print("Intercepted msg: ", crackedMsg)
    else:
        do = False

print("Enough hacking, bye bye!")