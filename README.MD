# Bitcoin Wallet Generator (BIP84 with Bech32)

This Python project generates a Bitcoin wallet using the BIP84 standard and outputs the wallet address, private key, and public key. The wallet is a Bech32 (SegWit) type wallet.

## Features
- Generate a mnemonic seed phrase using BIP39.
- Derive Bitcoin wallet addresses (BIP84, m/84'/0'/0'/0/0 path).
- Export wallet information including:
  - Bech32 (SegWit) Bitcoin address
  - Private key (WIF and Hex formats)
  - Public key (Hex format)
- Save the generated wallet information to a file with a timestamp.

## Installation

### Requirements
- Python 3.x
- `pip` (Python package installer)

### Install dependencies

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/bitcoinlibrarypy.git
   cd bitcoinlibrarypy
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the script to generate a wallet:
   ```bash
   python generate_wallet.py
   ```

2. The script will output:
   - A randomly generated seed phrase
   - Bech32 Bitcoin address
   - Private key (WIF and Hex)
   - Public key (Hex)

3. The wallet information will also be saved in a `.txt` file with a timestamp (e.g., `keys_20241015_123456.txt`).

### Example Output
```bash
Seed Phrases: legal ... thank year ... sausage worth ... winner thank ...
BTC Wallet Address (Bech32): bc1qxyz...abcd
BTC Private Key (WIF): L1aW4...123ABC
BTC Private Key (hex): 5d2c5...7e2b
BTC Public Key (hex): 02c72...8af3
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request or raise an issue to improve this project.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
