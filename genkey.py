from paramiko import RSAKey
import os
os.makedirs('keys', exist_ok=True)
RSAKey.generate(2048).write_private_key_file('keys/server_key')
print('Key generated')