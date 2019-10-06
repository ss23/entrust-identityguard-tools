# entrust-identityguard-tools
Tools for playing with Entrust IdentityGuard soft tokens, such as decrypting QR codes and generating secrets

# decode-qr-uri.py
Run this with the URI from a QR code to recieve the decrypted data. The decrypted data can be later combined with a registration code to derive the TOTP secrets.

Example:
```
$ ./generate-hmacs.py 'igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B' 54998317
{"sn":"48244-13456","ac":"1745-7712-6942-8698","policy":"{\"allowUnsecured\":\"false\",\"trustedExecution\":\"NOT_ALLOWED\"}","regurl":"myid.umc.edu\/igst"}
```
