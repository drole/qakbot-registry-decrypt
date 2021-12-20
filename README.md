# Qakbot Registry Key Configuration Decryptor

This is a decryptor for Qakbot's configuration stored in the registry key

## Python 3 requirements

```arc4==0.0.4
bitstring==3.1.9
hexdump==3.3
pycryptodome==3.12.0
WMI==1.5.1
```

## Usage

```
Usage: qakbot-registry-decrypt.py [options]

Options:
  -h, --help            show this help message and exit
  -r REGISTRY_PATH, --regpath=REGISTRY_PATH
                        registry path where Qakbot's encrypted data is stored.
                        (e.g. 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Efwramsn')
  -p PASSWORD, --password=PASSWORD
                        password (optional)
```