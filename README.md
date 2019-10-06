# entrust-identityguard-tools
Tools for playing with Entrust IdentityGuard soft tokens, such as decrypting QR codes and generating secrets

# decode-qr-uri.py
Run this with the URI from a QR code to recieve the decrypted data. The decrypted data can be later combined with a registration code to derive the TOTP secrets.

Example:
```
$ ./decode-qr-uri.py 'igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B' 54998317
{"sn":"48244-13456","ac":"1745-7712-6942-8698","policy":"{\"allowUnsecured\":\"false\",\"trustedExecution\":\"NOT_ALLOWED\"}","regurl":"myid.umc.edu\/igst"}
```

# generate-otp.py
Once you have the required information from a QR code, you can combine it with a "registration code" to derive the OTP secret. This registration code contains random bytes that were generated on the end-users device (their mobile phone), and are thus required to determine the OTP secret. An example way to obtain all of this information would be through email, if the user recieves a QR code in their email, then responds with their registration code.

Example:
```
$ ./generate-otp.py 48244-13456 1745-7712-6942-8698 12211-49352
9a8eab5ecc9fc413758a92ac223dc6a0

To generate a code immediately, run:
oathtool -v --totp=sha256 --digits=6 9a8eab5ecc9fc413758a92ac223dc6a0

$ oathtool -v --totp=sha256 --digits=6 9a8eab5ecc9fc413758a92ac223dc6a0
Hex secret: 9a8eab5ecc9fc413758a92ac223dc6a0
Base32 secret: TKHKWXWMT7CBG5MKSKWCEPOGUA======
Digits: 6
Window size: 0
Step size (seconds): 30
Start time: 1970-01-01 00:00:00 UTC (0)
Current time: 2019-10-06 08:50:31 UTC (1570351831)
Counter: 0x31EB8E5 (52345061)

814835
```
