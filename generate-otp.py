#!/bin/env python3
from hashlib import pbkdf2_hmac
import argparse
import logging

logging.basicConfig(level=logging.WARNING)

parser = argparse.ArgumentParser(
	description='Generate an OTP secret for an Entrust IdentityGuard soft token',
	epilog='If your token does not work, try without the Policy argument, as in some cases, this is not used to generate the OTP secret'
)
parser.add_argument('Serial', type=str, nargs=1, help='Given to the user (such as through a QR code). Example: 48244-13456')
parser.add_argument('ActivationCode', type=str, nargs=1, help='Given to the user (such as through a QR code). Example: 1745-7712-6942-8698')
parser.add_argument('RegistrationCode', type=str, nargs=1, help='The user provides this to the activation service. Example: 12211-49352')
parser.add_argument('--policy', type=str, nargs=1, required=False, help='The policy associated with the identity. Example: {"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}')
args = parser.parse_args()

# Remove dashes from input so we can work with the data
serial = args.Serial[0].replace("-", "")
activation = args.ActivationCode[0].replace("-", "")
registration = args.RegistrationCode[0].replace("-", "")

# TODO: Validate all values through the Luhn check digits

activation = activation[0:-1] # remove last digit -- check digit
activationbytes = int(activation).to_bytes(7, byteorder='big')
logging.info("Activation bytes: 0x%s", activationbytes.hex())

registration = registration[0:-1] # remove last digit -- check digit
registrationbytes = int(registration).to_bytes(4, byteorder='big')
logging.info("Registration bytes: 0x%s", registrationbytes.hex())

# Derive the RNG output from the registration bytes
# Remaining bits are used for validation, but we can ignore that in our case
rngbytes = registrationbytes[-2:]

logging.info("RNG Bytes: 0x%s", rngbytes.hex())

password = activationbytes + rngbytes

# The secret may or may not include the policy
if args.policy is not None:
	password += args.policy[0].encode('utf-8')
	logging.info("Policy: %s", args.policy[0].encode('utf-8'))
else:
	logging.debug("Policy not provided")

# Derive the secret key
key = pbkdf2_hmac(
    hash_name='sha256',
    password=password,
    salt=serial.encode("utf-8"),
    iterations=8,
    dklen=16
)

print(key.hex())
print("To generate a code immediately, run:")
print("oathtool -v --totp=sha256 --digits=6 " + key.hex())
