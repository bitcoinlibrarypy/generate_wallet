from mnemonic import Mnemonic
import bip32utils
import hashlib
import datetime
from bech32 import bech32_encode, convertbits

# Function to generate a new mnemonic seed phrase
def generate_mnemonic(strength=256):
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=strength)

# Function to convert seed phrase to binary seed
def seed_from_mnemonic(mnemonic_phrase):
    return Mnemonic.to_seed(mnemonic_phrase)

# Function to derive the account extended private key using BIP84 path: m/84'/0'/0'
def derive_account_key(seed, purpose=84, coin_type=0, account=0):
    root_key = bip32utils.BIP32Key.fromEntropy(seed)
    purpose_key = root_key.ChildKey(purpose + bip32utils.BIP32_HARDEN)
    coin_type_key = purpose_key.ChildKey(coin_type + bip32utils.BIP32_HARDEN)
    return coin_type_key.ChildKey(account + bip32utils.BIP32_HARDEN)

# Function to derive a Bech32 address from public key
def pubkey_to_bech32_address(pubkey_bytes, hrp="bc"):
    sha256_hash = hashlib.sha256(pubkey_bytes).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    converted_bits = convertbits(ripemd160_hash, 8, 5)
    return bech32_encode(hrp, [0] + converted_bits)

# Function to derive the first receiving address and return its keys
def derive_address_and_keys(account_key):
    change_key = account_key.ChildKey(0)
    address_key = change_key.ChildKey(0)
    public_key_bytes = address_key.PublicKey()

    return {
        "public_key_bytes": public_key_bytes,
        "private_key_wif": address_key.WalletImportFormat(),
        "private_key_hex": address_key.PrivateKey().hex(),
        "public_key_hex": public_key_bytes.hex(),
        "bech32_address": pubkey_to_bech32_address(public_key_bytes)
    }

# Function to save keys to a file with a timestamp
def save_keys_to_file(seed_phrase, wallet_info):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"keys_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(f"Seed Phrases: {seed_phrase}\n")
        f.write(f"BTC Wallet Address (Bech32): {wallet_info['bech32_address']}\n")
        f.write(f"BTC Private Key (WIF): {wallet_info['private_key_wif']}\n")
        f.write(f"BTC Private Key (hex): {wallet_info['private_key_hex']}\n")
        f.write(f"BTC Public Key (hex): {wallet_info['public_key_hex']}\n")

    print(f"Keys saved in {filename}")

# Main script execution
if __name__ == "__main__":
    # Generate mnemonic and convert it to seed
    seed_phrase = generate_mnemonic()
    seed = seed_from_mnemonic(seed_phrase)

    # Derive the account key and the first address
    account_key = derive_account_key(seed)
    wallet_info = derive_address_and_keys(account_key)

    # Output the wallet information
    print(f"Seed Phrases: {seed_phrase}")
    print(f"BTC Wallet Address (Bech32): {wallet_info['bech32_address']}")
    print(f"BTC Private Key (WIF): {wallet_info['private_key_wif']}")
    print(f"BTC Private Key (hex): {wallet_info['private_key_hex']}")
    print(f"BTC Public Key (hex): {wallet_info['public_key_hex']}")

    # Save the wallet info to a file
    save_keys_to_file(seed_phrase, wallet_info)
