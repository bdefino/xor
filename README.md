# `xor` - securely XOR files to STDOUT
Good encryption is tough to come by, and the theoretical usefulness of the One
Time Pad isn't all that easy in practice.  `xor` attempts to alleviate that.

Well, what makes this tool different from the tons of others out there?  Easy:
- it's simple--the CLI is already minimal,
- it's secure--the *single source file* is open, contains a breakdown on the
	precautions taken, plus it's easy to read/verify,
- and it **supports multiple input files**--this means you can *securely*
	encipher a plaintext with **multiple keys**.

Oh, and here's the full help text:
```
securely XOR files to STDOUT
Usage: xor FILE...
```
and an example:
```
# create a plaintext file

echo "some plaintext" > ptext

# generate random keys (of the same size: if they're too small, the XOR wraps
# around)

COUNT="$(wc -c ptext)"

for I in 1 2 3 4
do
	dd bs=1 count="${COUNT}" if=/dev/urandom of="key${I}"
done

# generate a ciphertext

xor key* ptext > ctext

# regenerate the plaintext

xor key* ctext > ptext.recovered

# compare

diff ptext*
```

