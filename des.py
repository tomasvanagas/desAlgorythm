import binascii
import os
import sys
import time
from threading import Thread
from time import sleep
import codecs


# ------ Binary - Hex utilities ------
def hextobin(hexval):
    thelen = len(hexval)*4
    binval = bin(int(hexval, 16))[2:]
    while ((len(binval)) < thelen):
        binval = '0' + binval
    return binval

def bintohex(binary):
    return hex(int(binary, 2))[2:].zfill(len(binary)//4).upper()

def bintoDec(binary):
    return int(binary, 2)

def dectobin(dec, binaryDigits):
    return bin(dec)[2:].zfill(binaryDigits)

# ------------------------------------


# --------- Binary Operations --------
def splitHalf(hexFull):
    binaryFull = hextobin(hexFull)
    keyLen = len(binaryFull)
    halfs = ["", ""]
    halfs[0] = bintohex(binaryFull[:int(keyLen/2)])
    halfs[1] = bintohex(binaryFull[int(keyLen/2):])
    return halfs

def shiftLeft(hex):
    binary = hextobin(hex)
    binary = str(binary[1:] + binary[0])
    hex = bintohex(binary)
    return hex

def xor(a, b):
    if(len(a) != len(b)):
        raise Exception("ERROR: (xor) Lengths does not match.")
    y = int(a, 2)^int(b,2)
    return bin(y)[2:].zfill(len(a))
# ------------------------------------


def initialPermutation(hexInput):
    # Plaintext pradinis apkeitimas
    if(len(hexInput)!=16):
        raise Exception("ERROR: (Initial permutation) Input length is wrong.")
    IP_TABLE =   (
        57, 49, 41, 33, 25, 17, 9,  1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7,
        56, 48, 40, 32, 24, 16, 8,  0,
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6 
    )

    binKey = hextobin(hexInput)

    # Apkeitimas
    afterInitialPermutation = ["0"]*64
    for i in range(len(binKey)):
        afterInitialPermutation[i] = binKey[IP_TABLE[i]]
    afterInitialPermutation = bintohex(''.join(afterInitialPermutation))

    return afterInitialPermutation


def generateKeys(originalKey):
    # Tikriname ar originalus raktas yra 64 bit
    if(len(originalKey)!=16):
        raise Exception("ERROR: (generate key) Input length is wrong.")
    
    # ------ Parity drop --------------------------------------------------------
    parityDrop = (
        56, 48, 40, 32, 24, 16, 8,
        0,  57, 49, 41, 33, 25, 17,
        9,  1,  58, 50, 42, 34, 26,
        18, 10, 2,  59, 51, 43, 35,
        62, 54, 46, 38, 30, 22, 14,
        6,  61, 53, 45, 37, 29, 21,
        13, 5,  60, 52, 44, 36, 28,
        20, 12, 4,  27, 19, 11, 3,
    )

    originalKeyBin = hextobin(originalKey)

    masterKeyBin =  ["0"]*56
    for i in range(len(masterKeyBin)):
        masterKeyBin[i] = originalKeyBin[parityDrop[i]]
    masterKeyHex = bintohex(''.join(masterKeyBin))
    # ---------------------------------------------------------------------------



    roundKeyListHex = ["0"]*16
    # ------ Round Keys Gen -----------------------------------------------------
    preRoundKeyHex = masterKeyHex
    for currentRound in range(1, 16+1):
        # Perstumimai
        roundHalfs = splitHalf(preRoundKeyHex)
        roundHalfs[0] = shiftLeft(roundHalfs[0])
        roundHalfs[1] = shiftLeft(roundHalfs[1])
        if( currentRound != 1 and 
            currentRound != 2 and 
            currentRound != 9 and 
            currentRound != 16 ):
            roundHalfs[0] = shiftLeft(roundHalfs[0])
            roundHalfs[1] = shiftLeft(roundHalfs[1])
        afterHalfShiftsBin = hextobin(roundHalfs[0] + roundHalfs[1])

        # Kompresijos D-Boxas
        compressionDbox = (
            13, 16, 10, 23, 0,  4,
            2,  27, 14, 5,  20, 9,
            22, 18, 11, 3,  25, 7,
            15, 6,  26, 19, 12, 1,
            40, 51, 30, 36, 46, 54,
            29, 39, 50, 44, 32, 47,
            43, 48, 38, 55, 33, 52,
            45, 41, 49, 35, 28, 31
        )
        roundKeyBin = ["0"]*48
        for i in range(len(roundKeyBin)):
            roundKeyBin[i] = afterHalfShiftsBin[compressionDbox[i]]
        roundKeyHex = bintohex(''.join(roundKeyBin))

        roundKeyListHex[currentRound - 1] = roundKeyHex
        preRoundKeyHex = bintohex(afterHalfShiftsBin)
    # ---------------------------------------------------------------------------
    return roundKeyListHex


def encrypt(cyphertextOriginalHex, keyHex, debug=False):
    if(len(cyphertextOriginalHex)!=16):
        raise Exception("ERROR: (encrypt) Plaintext length is wrong.")

    keysHex = generateKeys(keyHex)

    cyphertextHex = initialPermutation(cyphertextOriginalHex)
    if(debug):
        #print("+================================================================+")
        print("+------------------------ ENCRYPTION ----------------------------+")
        print("[*] PLAINTEXT: " + cyphertextOriginalHex)
        print("[*] AFTER INITIAL PERMUTATION: " + str(splitHalf(cyphertextHex)))

    # --------------- Des ciklai ---------------
    for round in range(16):
        if(round!=15):
            plaintextSplitHex = splitHalf(cyphertextHex)
            data = desFunction(plaintextSplitHex[1], keysHex[round])
            plaintextSplitHex[0] = bintohex(xor(hextobin(data), hextobin(plaintextSplitHex[0])))

            # Swapas 
            plaintextSplitHex = [plaintextSplitHex[1], plaintextSplitHex[0]]

            if(debug):
                print("[*] ROUND " + str(round + 1) + "  \t--- " + str(plaintextSplitHex) + " --- KEY: " + keysHex[round])
            cyphertextHex = plaintextSplitHex[0] + plaintextSplitHex[1]

    # Paskutinis be swapo
    plaintextSplitHex = splitHalf(cyphertextHex)
    data = desFunction(plaintextSplitHex[1], keysHex[15])
    plaintextSplitHex[0] = bintohex(xor(hextobin(data), hextobin(plaintextSplitHex[0])))
    if(debug):
            print("[*] ROUND " + str(16) + "  \t--- " + str(plaintextSplitHex) + " --- KEY: " + keysHex[15])
    cyphertextHex = plaintextSplitHex[0] + plaintextSplitHex[1]


    INVERSE_PERMUTATION = (
        39, 7,  47, 15, 55, 23, 63, 31,
        38, 6,  46, 14, 54, 22, 62, 30,
        37, 5,  45, 13, 53, 21, 61, 29,
        36, 4,  44, 12, 52, 20, 60, 28,
        35, 3,  43, 11, 51, 19, 59, 27,
        34, 2,  42, 10, 50, 18, 58, 26,
        33, 1,  41, 9,  49, 17, 57, 25,
        32, 0,  40, 8,  48, 16, 56, 24,
    )

    # Inverse Permutation
    cyphertextBin = hextobin(cyphertextHex)
    inversePermutationBin = ["0"]*64
    for i in range(len(inversePermutationBin)):
        inversePermutationBin[i] = cyphertextBin[INVERSE_PERMUTATION[i]]
    inversePermutationBin = ''.join(inversePermutationBin)
    cyphertextHex = bintohex(inversePermutationBin)
    if(debug):
        print("[*] CYPHERTEXT OUTPUT: " + cyphertextHex)
        print("+----------------------------------------------------------------+")
        #print("+================================================================+")
        print("\n")
    return cyphertextHex


def decrypt(cyphertextOriginalHex, keyHex, debug=False):
    if(len(cyphertextOriginalHex)!=16):
        raise Exception("ERROR: (decrypt) Cyphertexto length is wrong.")

    keysHex = generateKeys(keyHex)

    cyphertextHex = initialPermutation(cyphertextOriginalHex)
    if(debug):
        #print("+================================================================+")
        print("+------------------------ DECRYPTION ----------------------------+")
        print("[*] CYPHERTEXT INPUT: " + cyphertextOriginalHex)
        print("[*] AFTER INITIAL PERMUTATION: " + str(splitHalf(cyphertextHex)))

    # --------------- Des ciklai ---------------
    for round in reversed(range(16)):
        if(round!=0):
            plaintextSplitHex = splitHalf(cyphertextHex)
            data = desFunction(plaintextSplitHex[1], keysHex[round])
            plaintextSplitHex[0] = bintohex(xor(hextobin(data), hextobin(plaintextSplitHex[0])))

            # Swapas 
            plaintextSplitHex = [plaintextSplitHex[1], plaintextSplitHex[0]]

            if(debug):
                print("[*] ROUND " + str(round + 1) + "  \t--- " + str(plaintextSplitHex) + " --- KEY: " + keysHex[round])
            cyphertextHex = plaintextSplitHex[0] + plaintextSplitHex[1]

    # Paskutinis be swapo
    plaintextSplitHex = splitHalf(cyphertextHex)
    data = desFunction(plaintextSplitHex[1], keysHex[0])
    plaintextSplitHex[0] = bintohex(xor(hextobin(data), hextobin(plaintextSplitHex[0])))
    if(debug):
            print("[*] ROUND " + str(1) + "  \t--- " + str(plaintextSplitHex) + " --- KEY: " + keysHex[15])
    cyphertextHex = plaintextSplitHex[0] + plaintextSplitHex[1]


    INVERSE_PERMUTATION = (
        39, 7,  47, 15, 55, 23, 63, 31,
        38, 6,  46, 14, 54, 22, 62, 30,
        37, 5,  45, 13, 53, 21, 61, 29,
        36, 4,  44, 12, 52, 20, 60, 28,
        35, 3,  43, 11, 51, 19, 59, 27,
        34, 2,  42, 10, 50, 18, 58, 26,
        33, 1,  41, 9,  49, 17, 57, 25,
        32, 0,  40, 8,  48, 16, 56, 24,
    )

    # Inverse Permutation
    cyphertextBin = hextobin(cyphertextHex)
    inversePermutationBin = ["0"]*64
    for i in range(len(inversePermutationBin)):
        inversePermutationBin[i] = cyphertextBin[INVERSE_PERMUTATION[i]]
    inversePermutationBin = ''.join(inversePermutationBin)
    cyphertextHex = bintohex(inversePermutationBin)
    if(debug):
        print("[*] PLAINTEXT OUTPUT: " + cyphertextHex)
        print("+----------------------------------------------------------------+")
        #print("+================================================================+")
        print("\n")
    return cyphertextHex

    
def desFunction(cyphertextHex, keyHex):
    if(len(cyphertextHex)!=8):
        raise Exception("ERROR: (desFunction) CyphertextHex length is wrong.")
    if(len(keyHex)!=12):
        raise Exception("ERROR: (desFunction) keyHex length is wrong. " + str(len(keyHex)))

    # -------------------- Constants --------------------
    S_BOX = (
        (
            14, 4,  13, 1,  2,  15, 11, 8,  3,  10, 6,  12, 5,  9,  0,  7,
            0,  15, 7,  4,  14, 2,  13, 1,  10, 6,  12, 11, 9,  5,  3,  8,
            4,  1,  14, 8,  13, 6,  2,  11, 15, 12, 9,  7,  3,  10, 5,  0,
            15, 12, 8,  2,  4,  9,  1,  7,  5,  11, 3,  14, 10, 0,  6,  13,
        ),
        (
            15, 1,  8,  14, 6,  11, 3,  4,  9,  7,  2,  13, 12, 0,  5,  10,
            3,  13, 4,  7,  15, 2,  8,  14, 12, 0,  1,  10, 6,  9,  11, 5,
            0,  14, 7,  11, 10, 4,  13, 1,  5,  8,  12, 6,  9,  3,  2,  15,
            13, 8,  10, 1,  3,  15, 4,  2,  11, 6,  7,  12, 0,  5,  14, 9,
        ),
        (
            10, 0,  9,  14, 6,  3,  15, 5,  1,  13, 12, 7,  11, 4,  2,  8,
            13, 7,  0,  9,  3,  4,  6,  10, 2,  8,  5,  14, 12, 11, 15, 1,
            13, 6,  4,  9,  8,  15, 3,  0,  11, 1,  2,  12, 5,  10, 14, 7,
            1,  10, 13, 0,  6,  9,  8,  7,  4,  15, 14, 3,  11, 5,  2,  12,
        ),
        (
            7,  13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
            13, 8,  11, 5,  6,  15, 0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
            10, 6,  9,  0,  12, 11, 7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
            3,  15, 0,  6,  10, 1,  13, 8,  9,  4,  5,  11, 12, 7,  2,  14,
        ),
        (
            2,  12, 4,  1,  7,  10, 11, 6,  8,  5,  3,  15, 13, 0,  14, 9,
            14, 11, 2,  12, 4,  7,  13, 1,  5,  0,  15, 10, 3,  9,  8,  6,
            4,  2,  1,  11, 10, 13, 7,  8,  15, 9,  12, 5,  6,  3,  0,  14,
            11, 8,  12, 7,  1,  14, 2,  13, 6,  15, 0,  9,  10, 4,  5,  3,
        ),
        (
            12, 1,  10, 15, 9,  2,  6,  8,  0,  13, 3,  4,  14, 7,  5,  11,
            10, 15, 4,  2,  7,  12, 9,  5,  6,  1,  13, 14, 0,  11, 3,  8,
            9,  14, 15, 5,  2,  8,  12, 3,  7,  0,  4,  10, 1,  13, 11, 6,
            4,  3,  2,  12, 9,  5,  15, 10, 11, 14, 1,  7,  6,  0,  8,  13,
        ),
        (
            4,  11,  2, 14, 15, 0,  8,  13, 3,  12, 9,  7,  5,  10, 6,  1,
            13, 0,  11, 7,  4,  9,  1,  10, 14, 3,  5,  12, 2,  15, 8,  6,
            1,  4,  11, 13, 12, 3,  7,  14, 10, 15, 6,  8,  0,  5,  9,  2,
            6,  11, 13, 8,  1,  4,  10, 7,  9,  5,  0,  15, 14, 2,  3,  12,
        ),
        (
            13, 2,  8,  4,  6,  15, 11, 1,  10, 9,  3,  14, 5,  0,  12, 7,
            1,  15, 13, 8,  10, 3,  7,  4,  12, 5,  6,  11, 0,  14, 9,  2,
            7,  11, 4,  1,  9,  12, 14, 2,  0,  6,  10, 13, 15, 3,  5,  8,
            2,  1,  14, 7,  4,  10, 8,  13, 15, 12, 9,  0,  3,  5,  6,  11,
        ),
    )
    E_BOX = (
        31, 0,  1,  2,  3,  4,
        3,  4,  5,  6,  7,  8,
        7,  8,  9,  10, 11, 12,
        11, 12, 13, 14, 15, 16,
        15, 16, 17, 18, 19, 20,
        19, 20, 21, 22, 23, 24,
        23, 24, 25, 26, 27, 28,
        27, 28, 29, 30, 31, 0,
    )
    FIXED_PERMUTATION = (
        15, 6,  19, 20, 28, 11, 27, 16,
        0,  14, 22, 25, 4,  17, 30, 9,
        1,  7,  23, 13, 31, 26, 2,  8,
        18, 12, 29, 5,  21, 10, 3,  24,
    )
    # ---------------------------------------------------

    dataBin = hextobin(cyphertextHex)


    # --- Expansion
    expandedBin = ["0"]*48
    for i in range(len(expandedBin)):
        expandedBin[i] = dataBin[E_BOX[i]]
    dataBin = ''.join(expandedBin)

    #print(bintohex(dataBin))


    # --- XOR
    dataBin = xor(dataBin, hextobin(keyHex))


    # Substitution
    afterSubstitutionBin = ""
    for chunkNum in range(8):
        chunkBin = dataBin[int(6*chunkNum):int(6*(chunkNum+1)) ]
        rowDec = bintoDec(chunkBin[0] + chunkBin[5])
        columnDec = bintoDec(chunkBin[1:5])
        #print("Row: " + str(rowDec) + "   Column: " + str(columnDec))
        substitutionItemId = rowDec*16 + columnDec
        substitutionItemBin = dectobin(S_BOX[chunkNum][substitutionItemId], 4)
        afterSubstitutionBin += substitutionItemBin
    dataBin = afterSubstitutionBin


    # Fixed Permutation
    fixedPermutation = ["0"]*32
    for i in range(len(dataBin)):
        fixedPermutation[i] = dataBin[FIXED_PERMUTATION[i]]
    dataBin = ''.join(fixedPermutation)
    return bintohex(dataBin)


def clearScreen():
    os.system('cls' if os.name == 'nt' else 'clear')


def asciiArt():
    clearScreen()
    print("+=============================================================================================================+")
    print("+=============================================================================================================+")
    print("+=============================================================================================================+")
    print( "                                                                                    ")
    print( "                        DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEE   SSSSSSSSSSSSSSS ")
    print( "                        D::::::::::::DDD   E::::::::::::::::::::E SS:::::::::::::::S")
    print( "                        D:::::::::::::::DD E::::::::::::::::::::ES:::::SSSSSS::::::S")
    print( "                        DDD:::::DDDDD:::::DEE::::::EEEEEEEEE::::ES:::::S     SSSSSSS")
    print( "                          D:::::D    D:::::D E:::::E       EEEEEES:::::S            ")
    print( "                          D:::::D     D:::::DE:::::E             S:::::S            ")
    print( "                          D:::::D     D:::::DE::::::EEEEEEEEEE    S::::SSSS         ")
    print( "                          D:::::D     D:::::DE:::::::::::::::E     SS::::::SSSSS    ")
    print( "                          D:::::D     D:::::DE:::::::::::::::E       SSS::::::::SS  ")
    print( "                          D:::::D     D:::::DE::::::EEEEEEEEEE          SSSSSS::::S ")
    print( "                          D:::::D     D:::::DE:::::E                         S:::::S")
    print( "                          D:::::D    D:::::D E:::::E       EEEEEE            S:::::S")
    print( "                        DDD:::::DDDDD:::::DEE::::::EEEEEEEE:::::ESSSSSSS     S:::::S")
    print( "                        D:::::::::::::::DD E::::::::::::::::::::ES::::::SSSSSS:::::S")
    print( "                        D::::::::::::DDD   E::::::::::::::::::::ES:::::::::::::::SS ")
    print( "                        DDDDDDDDDDDDD      EEEEEEEEEEEEEEEEEEEEEE SSSSSSSSSSSSSSS   ")
    print( "                                                                                    ")
    print("+=============================================================================================================+")
    print("+=============================================================================================================+")
    print("+=============================================================================================================+")

def printLogo():
    clearScreen()
    print("+=========================================================================+")
    print("+================================== DES ==================================+")
    print("+=========================================================================+\n\n")


def menu():
    sys.stdout.write("\x1b[8;{rows};{cols}t".format(rows=70, cols=200))
    asciiArt()
    time.sleep(2)
    
    while(True):
        printLogo()
        
        # Plaintext įvedimas
        plaintext = input("Submit your plaintext: ")
        if(len(plaintext)>8):
            printLogo()
            print("[*] ERROR: plaintext should NOT be longer than 8 symbols.\n")
            input("Press ENTER to continue...")
            continue
        elif(len(plaintext)<8):
            while(len(plaintext)<8):
                plaintext += " "

        # Rakto įvedimas
        key = input("\nSubmit your key (hex format 16 symbol length): ")
        if(len(key)==0):
            print("[*] Used default key (abcdef1234567890).\n")
            key = "abcdef1234567890"
        elif(len(key)!=16):
            printLogo()
            print("[*] ERROR: Key should be 16 symbols length.\n")
            input("Press ENTER to continue...")
            continue



        hexString = codecs.encode(plaintext.encode(),'hex')
        plainHex = str(str(hexString)[2:-1])
        hexEnc = encrypt(plainHex, key, debug=True)
        hexDecrypted = decrypt(hexEnc, key, debug=True)

        plaintextDecrypted = codecs.decode(hexDecrypted,'hex').decode()
        print("\n[*] Decyphered text: ----->" + plaintextDecrypted + "<-----\n")
        input("Press ENTER to continue...")

menu()
