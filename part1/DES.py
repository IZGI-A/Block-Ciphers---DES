from util import *


class DES:
    # DO NOT CHANGE
    # THESE ARE TABLES THAT DES USE FOR PERMUTATIONS
    ENCRYPTION = 0
    DECRYPTION = 1

    PC1 = [56, 48, 40, 32, 24, 16, 8,
           0, 57, 49, 41, 33, 25, 17,
           9, 1, 58, 50, 42, 34, 26,
           18, 10, 2, 59, 51, 43, 35,
           62, 54, 46, 38, 30, 22, 14,
           6, 61, 53, 45, 37, 29, 21,
           13, 5, 60, 52, 44, 36, 28,
           20, 12, 4, 27, 19, 11, 3
           ]

    PC2 = [
        13, 16, 10, 23, 0, 4,
        2, 27, 14, 5, 20, 9,
        22, 18, 11, 3, 25, 7,
        15, 6, 26, 19, 12, 1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    ]

    LEFT_ROTATIONS = [
        1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
    ]
    #Initial Permutation
    IP = [57, 49, 41, 33, 25, 17, 9, 1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7,
          56, 48, 40, 32, 24, 16, 8, 0,
          58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6
          ]

    E = [
        31, 0, 1, 2, 3, 4,
        3, 4, 5, 6, 7, 8,
        7, 8, 9, 10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0
    ]

    S_BOXES = [
        # S1
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
         0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
         4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
         15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

        # S2
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
         3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
         0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
         13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

        # S3
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
         13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
         13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
         1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

        # S4
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
         13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
         10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
         3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

        # S5
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
         14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
         4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
         11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

        # S6
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
         10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
         9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
         4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

        # S7
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
         13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
         1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
         6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

        # S8
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
         1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
         7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
         2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]

    P = [
        15, 6, 19, 20, 28, 11,
        27, 16, 0, 14, 22, 25,
        4, 17, 30, 9, 1, 7,
        23, 13, 31, 26, 2, 8,
        18, 12, 29, 5, 21, 10,
        3, 24
    ]
    #Final Permutation
    FP = [
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25,
        32, 0, 40, 8, 48, 16, 56, 24
    ]

    def __init__(self, publicKey: bytes, IV: bytes, mode="ECB"):
        """
        This is the init function for the DES. The DES takes a public key and Initial Value (if the mode is CBC).
        The initialization of the class is complete. You don't need to change anything in the code below. You should
        implement two modes; ECB and CBC. And you should send the key and initial value as bytes.
        """
        # Check the key and IV format
        if len(publicKey) != 8:
            raise ValueError("Invalid key size! Key should be exactly 8 bytes.")
        if len(IV) != 8:
            raise ValueError("Invalid Initial Value (IV)! Must be 8 bytes.")

        self.publicKey = publicKey
        self.IV = IV
        self.mode = mode
        self.block_size = 8

        self.L, self.R = list(), list()
        self.Kn = [[0] * 48] * 16  # 16 48-bit sub-keys
        self.final = list()

        # Initiate the subkey loop
        self.generate_subkeys()

    def generate_subkeys(self):
        """
        This function generates key-schedule of DES. And saves the resulting 16 subkeys in to array Kn.
        Kn is an array that stores 16 subkeys generated by this function. And each subkey is 48-bit stored
        from Kn[0] to Kn[15].
        """

        # Complete the DES key schedule
        # Use permutation and rotation tables above
        #################################
        # YOUR CODE HERE
        #################################
        self.publicKey = stringToBits(self.publicKey)
        print("BIT PUBLIC KEY",(self.publicKey))
        print(len(self.publicKey))

        parity_drop_key = permutation(self.publicKey, self.PC1)
        print("PARITY DROP KEY", parity_drop_key)
        print(len(parity_drop_key))
        self.L = parity_drop_key[:28]
        self.R = parity_drop_key[28:]

        for i in range(16):
            self.L = self.L[self.LEFT_ROTATIONS[i]:] + self.L[:self.LEFT_ROTATIONS[i]]
            self.R = self.R[self.LEFT_ROTATIONS[i]:] + self.R[:self.LEFT_ROTATIONS[i]]

            LeftRight = self.L + self.R
            print("SUB KEY", (LeftRight))
            subkey = permutation(LeftRight, self.PC2)

            self.Kn[i] = subkey

        print(self.Kn)

    def _chunk_crypt(self, block, crypt_type):
        """
        This function cryptes to 64-bit chunk of data.
        This function is a core function that will be
        used by other functions.

        The function will take 64-bit sized blocks and crypt type (ENCRYPTION or DECRYPTION).
        And it will return the encrypted/decrypted value into the variable 'final'.
        Important Note: If the mode is Decryption you should use subkeys in Kn in reverse order.

        Inputs:
            block: A bytearray, 64-bit sized blocks of the data
            crypt_type: A constant value, if encrypt it is self.ENCRYPT, if decrypt it is self.DECRYPT
        Output:
            self.final: It is a storage value, holds the value of the final state after the last step
        """
        # COMPLETE THE CODE BELOW
        # Start with initial permutation and split your 64 bits input into two halves.
        # If the mode is encryption start from Kn[0] to Kn[15]
        # Else start from Kn[15] to Kn[0]
        # Start Feistel Function for every subkey
        # Concat left and right halves
        # Final permutation with FP table
        # Save results to self.final
        #######################################
        # YOUR CODE HERE
        #######################################

        # Apply the initial permutation using IP
        block = permutation(block, self.IP)

        # Split the block into left and right halves
        self.L = block[:32]
        self.R = block[32:]

        # Use subkeys in reverse order for decryption
        if crypt_type == self.DECRYPTION:
            self.Kn = self.Kn[::-1]

        # Perform 16 rounds of Feistel network
        for i, subkey in enumerate(self.Kn):
            # Save the current values of L and R
            L_temp = self.L.copy()
            R_temp = self.R.copy()

            # Expand and permute R using E table
            expanded_R = permutation(R_temp, self.E)

            # XOR the expanded R with the subkey
            xor_result = xor(expanded_R, subkey)

            # Apply S-box substitution
            s_box_output = self.s_box_substitution(xor_result)
            #print("SBOx: ", s_box_output)
            # Permute the result using P table
            permuted_result = permutation(s_box_output, self.P)
            #print("PERMUTED: ", permuted_result)
            # XOR the permuted result with the original L
            new_L = xor(L_temp, permuted_result)

            # Swap L and R for the next round
            self.L, self.R = R_temp, new_L

        # Combine the final L and R
        final_block = self.L + self.R

        # Apply the final permutation using FP
        self.final = permutation(final_block, self.FP)
        print("FINAL: ", len(self.final))
        return self.final


    def s_box_substitution(self, data):
        # Implement the S-box substitution logic using the provided S-boxes
        result = []
        s_box_input = [data[i:i+6] for i in range(0, len(data), 6)]

        for i in range(8):
            row = (s_box_input[i][0] * 2 + s_box_input[i][-1])# Calculate row index

            column = s_box_input[i][1:-1]
            column_binary = ''.join(str(bit) for bit in column)

            column = int(column_binary, 2)

            output_value = self.S_BOXES[i][row * 16 + column]

            output_bits = format(output_value, '04b')  # Convert to 4-bit binary

            result.append(output_bits)
        result = ''.join(result)
        result = [int(bit) for bit in result]

        return result


    def crypt(self, data, crypt_type):
        """
        Takes whole data, and runs it through _chunk_crypt(). You should implement the ECB and CBC modes here.
        The overall structure and conditions are given. You should fill the blanks to implement the logic.

        Inputs:
            data: It is a bytearray, the data to crypt.
            crypt_type: A constant value, if encrypt it is self.ENCRYPT, if decrypt it is self.DECRYPT
        """

        # Data sanity check before starting. Do not change codes.
        if len(data) % self.block_size != 0:
            if crypt_type == self.DECRYPTION:
                raise ValueError("Invalid data length. The encrypted file is corrupted.\n")
            else:
                data += (self.block_size - (len(data) % self.block_size)) * None
        if self.mode == "CBC":
            # We will need IV if the mode is CBC.
            iv = stringToBits(self.IV)

        # Split the data into blocks
        i = 0
        result = list()
        while i < len(data):
            block = stringToBits(data[i:i + 8])

            # XOR with IV if the mode is CBC
            if self.mode == "CBC":
                # Implement the CBC logic here. Consider both encryption and decryption.
                # The mode is given by the parameter crypt_type
                # You should get the result in a variable named 'cipherBlock'

                #######################################
                # YOUR CODE HERE
                #######################################
                print()

            # If the mode is ECB
            else:
                # Implement the ECB logic here.
                # You should get the result in a variable named 'cipherBlock'
                #######################################
                # YOUR CODE HERE
                #######################################
                cipherBlock = self._chunk_crypt(block, crypt_type)

            result.append(bitsToString(cipherBlock))
            i += 8
        print("RESULT: ", result)
        return bytes.fromhex('').join(result)

    def encrpyt(self, data: bytearray):
        """
        This function is a generic function that uses your implementation above.
        Takes data as byte array and directs it to the corresponding functions.
        Do not change this function.
        """
        data = validateEncoding(data)
        data = padData(data, self.block_size)
        return self.crypt(data, self.ENCRYPTION)

    def decrypt(self, data: bytearray):
        """
        This function is a generic function that uses your implementation above.
        Takes data as byte array and directs it to the corresponding functions.
        Do not change this function.
        """
        data = validateEncoding(data)
        data = self.crypt(data, self.DECRYPTION)
        print(unpadData(data))
        return unpadData(data)


def handleKey(key: str):
    """
    Handles the key and the IV for DES.
    You should input a key string and
    convert the key to a byte-array that
    can be usable for DES.
    """
    ############################
    # YOUR CODE HERE
    ############################
    key = key.encode('utf-8')
    key = key.ljust(8, b'\0')[:8]
    return key


def test(inputfile: str, publickey: str, IV: str, mode="ECB", save=True, cipher_mode="e"):
    """
    A test function to test your DES module. You will input the path of the input file, publickey and IV with other
    settings. If the save flag is active the outputs will be saved. The filenames are hardcoded you can change codes.
    If everything is correct, you should be able to restore the encrypted file by using decryption.
    """
    publickey = handleKey(publickey)
    print(publickey)
    IV = handleKey(IV)
    print(IV)

    cipher = DES(publickey, IV, mode=mode)
    if cipher_mode == "e":
        result = cipher.encrpyt(readBytesFromFile(inputfile))
    elif cipher_mode == "d":
        result = cipher.decrypt(readBytesFromFile(inputfile))
        result = bytearray(result)
        # result = result.decode('ascii')
    else:
        raise ValueError("Cipher mode should be 'e' for encryption, 'd' for decryption.")

    if save:
        filename = "encrypted.txt" if cipher_mode == "e" else "restored.txt"
        with open(filename, "wb") as f:
            f.write(result)
    else:
        print(result)
        return result


if __name__ == "__main__":
    publickey = "sample"
    #publickey = "elpmas"
    IV = "initial"
    #IV = "laitini"
    res = test("test.txt", publickey, IV, save=True)

