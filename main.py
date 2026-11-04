"""Interactive demonstration. The decryption key always comes from input()."""
import sys
from attacker import attack_package
from decrypt import decrypt_message
from package_io import DEFAULT_PACKAGE, load_package, save_package
from sender import encrypt_message
from shor import AttackFailure

MENU = '''
=======================================
 QUANTUM RSA ATTACK DEMONSTRATION
=======================================
[1] Encrypt Message
[2] Run Shor / Recover AES Key
[3] Decrypt Message (Manual AES Key)
[4] Exit
======================================='''


def encrypt_option(path):
    overwrite = False
    if path.exists():
        if input('Replace existing encrypted package? [y/N]: ').strip().lower() != 'y':
            print('Package replacement cancelled.')
            return
        overwrite = True
    package = encrypt_message(input('Enter plaintext: '))
    save_package(package, path, overwrite=overwrite)
    print('AES-256-GCM encryption and toy RSA key protection complete.')
    print('RSA public key: N=33, e=3')
    print('AES ciphertext plus tag:', package['ciphertext_and_tag_hex'])
    print('Encrypted AES key:', package['header']['wrapped_key_digits'])
    print('Saved', path)


def attack_option(path):
    package = load_package(path)
    print('Target RSA modulus: 33; base: 5. Executing quantum simulation ...', flush=True)
    key, exponent, evidence = attack_package(package)
    print('Most frequent counting-register measurements:')
    for bits, count in sorted(evidence['counts'].items(), key=lambda item: (-item[1], item[0]))[:10]:
        print(f'  {bits}: {count} (phase {int(bits, 2)/4096:.6f})')
    print(f"Accepted sample: {evidence['sample']}; phase: {evidence['phase']:.6f}")
    print(f"Continued fraction: {evidence['convergent']}; validated order: {evidence['order']}")
    print(f"Factors recovered: {evidence['factors']}; private exponent: {exponent}")
    print(f"Shots: {evidence['shots']}; elapsed: {evidence['elapsed_seconds']:.3f}s")
    print('\nCANDIDATE RECOVERED AES-256 KEY (HEX):')
    print(key.hex())
    print('AES-GCM authentication has not been checked. Copy the key, then select [3].')


def decrypt_option(path):
    package = load_package(path)
    entered_key = input('Enter recovered AES-256 key (64 hex characters):\n> ')
    plaintext = decrypt_message(package, entered_key)
    print('AES-GCM authentication successful.\n\nRECOVERED PLAINTEXT:')
    print(plaintext)


def main(path=DEFAULT_PACKAGE):
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
    print('Educational RSA-33: trivially insecure; local classical quantum simulation.')
    while True:
        try:
            print(MENU)
            choice = input('Select option: ').strip()
            if choice == '4':
                return
            if choice not in ('1', '2', '3'):
                print('Choose 1, 2, 3, or 4.')
                continue
            try:
                {'1': encrypt_option, '2': attack_option, '3': decrypt_option}[choice](path)
            except (ValueError, OSError, AttackFailure) as error:
                print(f'Error: {error}')
            input('Press Enter to return to menu...')
        except (EOFError, KeyboardInterrupt):
            print('\nExiting.')
            return


if __name__ == '__main__':
    main()
