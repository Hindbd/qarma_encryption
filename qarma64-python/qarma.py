import tkinter as tk
from tkinter import StringVar, messagebox
import random

# selection of used sbox
sbox0 = [0, 14, 2, 10, 9, 15, 8, 11, 6, 4, 3, 7, 13, 12, 1, 5]
used_sbox = sbox0
used_sbox_inv = [used_sbox.index(x) for x in range(16)]

state_permutation = [0, 11, 6, 13, 10, 1, 12, 7, 5, 14, 3, 8, 15, 4, 9, 2]
state_permutation_inv = [state_permutation.index(x) for x in range(16)]
tweak_permutation = [6, 5, 14, 15, 0, 1, 2, 3, 7, 12, 13, 4, 8, 9, 10, 11]

def HexToBlock(hexstring):
    return [int(b, 16) for b in hexstring]

def BlockToHex(block):
    return "".join([hex(b)[2:].zfill(2) for b in block])  # Ensure 2 digits for each byte

alpha_string = "C0AC29B7C97C50DD"
alpha = HexToBlock(alpha_string)

round_constants_string = [
    "0000000000000000",
    "13198A2E03707344",
    "A4093822299F31D0",
    "082EFA98EC4E6C89",
    "452821E638D01377",
    "BE5466CF34E90C6C",
    "3F84D5B5B5470917",
    "9216D5D98979FB1B"
]

round_constants = [HexToBlock(s) for s in round_constants_string]

def SubBytes(state, inverse):
    if not inverse:
        return [used_sbox[b] for b in state]
    else:
        return [used_sbox_inv[b] for b in state]

def XorBlocks(a, b):
    return [x ^ y for x, y in zip(a, b)]

def rot(b, r):
    return ((b << r) | (b >> (4 - r))) % 16

def MixColumns_M41(col):
    newcol = [0] * 4
    newcol[0] = rot(col[1], 1) ^ rot(col[2], 2) ^ rot(col[3], 3)
    newcol[1] = rot(col[0], 3) ^ rot(col[2], 1) ^ rot(col[3], 2)
    newcol[2] = rot(col[0], 2) ^ rot(col[1], 3) ^ rot(col[3], 1)
    newcol[3] = rot(col[0], 1) ^ rot(col[1], 2) ^ rot(col[2], 3)
    return newcol

def MixColumns_M43(col):
    newcol = [0] * 4
    newcol[0] = rot(col[1], 1) ^ rot(col[2], 2) ^ rot(col[3], 1)
    newcol[1] = rot(col[0], 1) ^ rot(col[2], 1) ^ rot(col[3], 2)
    newcol[2] = rot(col[0], 2) ^ rot(col[1], 1) ^ rot(col[3], 1)
    newcol[3] = rot(col[0], 1) ^ rot(col[1], 2) ^ rot(col[2], 1)
    return newcol

UsedMixColumns = MixColumns_M43

def MixColumns(state):
    mixed_state = [0 for _ in range(16)]
    for i in range(4):
        incol = [state[0 + i], state[4 + i], state[8 + i], state[12 + i]]
        outcol = UsedMixColumns(incol)
        mixed_state[0 + i], mixed_state[4 + i], mixed_state[8 + i], mixed_state[12 + i] = outcol
    return mixed_state

def PermuteTweak(tweak):
    return [tweak[i] for i in tweak_permutation]

def PermuteState(state, inverse):
    if inverse:
        return [state[i] for i in state_permutation_inv]
    else:
        return [state[i] for i in state_permutation]

def TweakLFSR(tweak):
    for b in [0, 1, 3, 4, 8, 11, 13]:
        t = tweak[b]
        b3, b2, b1, b0 = (t >> 3) & 1, (t >> 2) & 1, (t >> 1) & 1, (t >> 0) & 1
        tweak[b] = ((b0 ^ b1) << 3) | (b3 << 2) | (b2 << 1) | (b1 << 0)
    return tweak

def CalcTweak(tweak, r):
    tweak_r = tweak
    for i in range(r):
        tweak_r = PermuteTweak(tweak_r)
        tweak_r = TweakLFSR(tweak_r)
    return tweak_r

def CalcRoundTweakey(tweak, r, k0, backwards):
    tweakey = CalcTweak(tweak, r)
    tweakey = XorBlocks(tweakey, k0)
    tweakey = XorBlocks(tweakey, round_constants[r])
    if backwards:
        tweakey = XorBlocks(tweakey, alpha)
    return tweakey

def Round(state, tweakey, r, backwards):
    # short round 0
    if not backwards:
        state = XorBlocks(state, tweakey)
        if r != 0:
            state = PermuteState(state, False)
            state = MixColumns(state)
        state = SubBytes(state, False)
        return state
    else:
        state = SubBytes(state, True)
        if r != 0:
            state = MixColumns(state)
            state = PermuteState(state, True)
        state = XorBlocks(state, tweakey)
        return state

def MiddleRound(state, k1):
    state = PermuteState(state, False)
    state = MixColumns(state)
    state = XorBlocks(state, k1)
    state = PermuteState(state, True)
    return state

def qarma64(plaintext, tweak, key, encryption=True, rounds=5):
    # Ensure rounds is within the expected range (1 to 7)
    if rounds < 1 or rounds > 7:
        raise ValueError("Number of rounds must be between 1 and 7.")

    # Key schedule preparation
    w0, k0 = key[:16], key[16:]
    w0_int = int(w0, 16)
    w1_int = ((w0_int >> 1) | ((w0_int & 1) << 63)) ^ (w0_int >> 63)
    w1 = hex(w1_int)[2:].rstrip("L").rjust(16, "0")

    # Convert hex values to blocks
    w0, w1, k0 = HexToBlock(w0), HexToBlock(w1), HexToBlock(k0)
    p, t = HexToBlock(plaintext), HexToBlock(tweak)

    # Setup keys for encryption/decryption
    k1 = k0 if encryption else MixColumns(k0)
    if not encryption:
        w0, w1 = w1, w0
        k0 = XorBlocks(k0, alpha)

    # Initial state
    state = XorBlocks(p, w0)

    # Encryption rounds
    for i in range(rounds):
        tweakey = CalcRoundTweakey(t, i, k0, False)
        state = Round(state, tweakey, i, False)

    # Final transformations
    tweakey = CalcTweak(t, rounds)
    state = Round(state, XorBlocks(w1, tweakey), rounds, False)
    state = MiddleRound(state, k1)
    state = Round(state, XorBlocks(w0, tweakey), rounds, True)

    # Decryption rounds
    # for i in reversed(range(rounds)):
    #     tweakey = CalcRoundTweakey(t, i, k0, True)
    #     state = Round(state, tweakey, i, True)

    # Final cipher output
    cipher = XorBlocks(state, w1)

    return BlockToHex(cipher)

# Function to generate a random 16-character hexadecimal value
def generate_random_hex():
    return ''.join(random.choice('0123456789abcdef') for _ in range(16))

def text_to_hex(text):
    return text.encode('utf-8').hex()

# Function to pad any hex input to 16 characters (64 bits)
def pad_to_64_bits(hex_string):
    return hex_string.rjust(16, '0')  # Pad with leading zeros to make it 16 characters
# Function to handle encryption when the user presses the button
# Function to remove padding after decryption
def remove_padding(text):
    return text.lstrip('0')  # Remove leading zeros (simple padding scheme)
def run_encryption():
    try:
        # Get values from the input fields
        P = plaintext_var.get()
        T = tweak_var.get()
        w0 = w0_var.get()
        k0 = k0_var.get()
        rounds = int(rounds_var.get())

        # Debug: Print the number of rounds to check if it updates correctly
        print(f"Encrypting with {rounds} rounds...")

        # Check if the input is in hex, if not, convert it
        if not all(c in '0123456789abcdefABCDEF' for c in P):
            P = text_to_hex(P)
            print(f"Converted plaintext to hex: {P}")

        # Pad the plaintext, tweak, w0, and k0 to 16 characters (64 bits)
        P = pad_to_64_bits(P)
        T = pad_to_64_bits(T)
        w0 = pad_to_64_bits(w0)
        k0 = pad_to_64_bits(k0)

        # Debug: Print padded inputs to verify correct padding
        print(f"Padded Plaintext: {P}, Tweak: {T}, w0: {w0}, k0: {k0}")

        # Encrypt using the current parameters
        ciphertext = qarma64(P, T, w0 + k0, rounds=rounds)

        # Debug: Print the encryption result
        print(f"Encryption result: {ciphertext}")

        # Display the result in the GUI
        result_var.set(f"Ciphertext: {ciphertext}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# def run_decryption():
#     C = ciphertext_var.get()
#     T = tweak_var.get()
#     w0 = w0_var.get()
#     k0 = k0_var.get()
#     rounds = int(rounds_var.get())
#
#     plaintext_padded = qarma64(C, T, w0 + k0, encryption=False, rounds=rounds)
#
#     # Remove padding after decryption
#     plaintext_hex = remove_padding(plaintext_padded)
#     # Convert the hex-encoded plaintext to ASCII
#     try:
#         plaintext = bytes.fromhex(plaintext_hex).decode('utf-8')  # Attempt to decode as UTF-8
#     except ValueError:
#         plaintext = plaintext_hex  # If it fails, just display the hex
#
#     decrypted_result_var.set(f"Decrypted Plaintext: {plaintext}")
# Function to generate random values for keys and tweak
def generate_random_w0():
    w0_var.set(generate_random_hex())

def generate_random_k0():
    k0_var.set(generate_random_hex())

def generate_random_tweak():
    tweak_var.set(generate_random_hex())

# Set up the GUI window
window = tk.Tk()
window.title("QARMA-64 Encryption")
window.geometry("450x350")
window.configure(bg="#2e2e2e")  # Dark background

# Styling
font_style = ("Helvetica", 12)
entry_bg = "#4e4e4e"  # Dark grey for entry fields
entry_fg = "#ffffff"  # White text in entry fields
label_bg = "#2e2e2e"  # Dark grey background for labels
label_fg = "#ffffff"  # White text for labels
button_bg = "#5A9"    # Button green color
button_fg = "#ffffff" # White button text
result_fg = "#00FF00" # Green result text

# Create input fields and labels
tk.Label(window, text="Plaintext:", bg=label_bg, fg=label_fg, font=font_style).grid(row=0, column=0, padx=10, pady=5)
plaintext_var = StringVar(value="fb623599da6e8127")  # Default value
tk.Entry(window, textvariable=plaintext_var, bg=entry_bg, fg=entry_fg, font=font_style).grid(row=0, column=1, padx=10, pady=5)

tk.Label(window, text="Tweak:", bg=label_bg, fg=label_fg, font=font_style).grid(row=1, column=0, padx=10, pady=5)
tweak_var = StringVar(value="477d469dec0b8762")  # Default value
tk.Entry(window, textvariable=tweak_var, bg=entry_bg, fg=entry_fg, font=font_style).grid(row=1, column=1, padx=10, pady=5)
tk.Button(window, text="Random Tweak", command=generate_random_tweak, bg=button_bg, fg=button_fg, font=("Helvetica", 10)).grid(row=1, column=2, padx=10)

tk.Label(window, text="W0 Key:", bg=label_bg, fg=label_fg, font=font_style).grid(row=2, column=0, padx=10, pady=5)
w0_var = StringVar(value="84be85ce9804e94b")  # Default value
tk.Entry(window, textvariable=w0_var, bg=entry_bg, fg=entry_fg, font=font_style).grid(row=2, column=1, padx=10, pady=5)
tk.Button(window, text="Random W0", command=generate_random_w0, bg=button_bg, fg=button_fg, font=("Helvetica", 10)).grid(row=2, column=2, padx=10)

tk.Label(window, text="K0 Key:", bg=label_bg, fg=label_fg, font=font_style).grid(row=3, column=0, padx=10, pady=5)
k0_var = StringVar(value="ec2802d4e0a488e9")  # Default value
tk.Entry(window, textvariable=k0_var, bg=entry_bg, fg=entry_fg, font=font_style).grid(row=3, column=1, padx=10, pady=5)
tk.Button(window, text="Random K0", command=generate_random_k0, bg=button_bg, fg=button_fg, font=("Helvetica", 10)).grid(row=3, column=2, padx=10)

tk.Label(window, text="Rounds:", bg=label_bg, fg=label_fg, font=font_style).grid(row=4, column=0, padx=10, pady=5)
rounds_var = StringVar(value="5")  # Default value is 5 rounds
tk.Entry(window, textvariable=rounds_var, bg=entry_bg, fg=entry_fg, font=font_style).grid(row=4, column=1, padx=10, pady=5)

# Display the result of encryption
result_var = StringVar()
result_label = tk.Label(window, textvariable=result_var, bg=label_bg, fg=result_fg, font=font_style)
result_label.grid(row=6, column=0, columnspan=2, padx=10, pady=10)

# Button to trigger the encryption
tk.Button(window, text="Encrypt", command=run_encryption, bg=button_bg, fg=button_fg, font=font_style).grid(row=5, column=1, pady=10)
# Additional input for ciphertext (for decryption)
# tk.Label(window, text="Ciphertext (for decryption):").grid(row=7, column=0)
# ciphertext_var = StringVar()
# tk.Entry(window, textvariable=ciphertext_var).grid(row=7, column=1)

# Display the result of decryption
# decrypted_result_var = StringVar()
# tk.Label(window, textvariable=decrypted_result_var).grid(row=9, column=1)
#
# # Button to trigger the decryption
# tk.Button(window, text="Decrypt", command=run_decryption).grid(row=8, column=1)

# Start the GUI event loop
window.mainloop()