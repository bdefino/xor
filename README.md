# `xor` - securely XOR files to STDOUT
Good encryption is tough to come by, and the theoretical usefulness of the One
Time Pad isn't all that easy in practice.  `xor` attempts to alleviate that.

Well, what makes this tool different from the tons of others out there?  Easy:
- it's simple--the CLI is already minimal,
- it's secure--the *single source file* is open, contains a breakdown on the
	precautions taken, plus it's easy to read/verify,
- and it **supports multiple input files**--this means you can *securely*
	encipher a plaintext with **multiple keys**.

> In the name of security, this is extremely slow: in fact, it only encrypts a
> single character at a time!  That way, if an attacker is able to recover
> pages from its address space, loss of cryptographic secrets is minimized.
> This approach is hugely advantageous over trust-based alternatives, such as a
> dedicated cryptographic coprocessor, or using a dedicated machine for
> cryptographic purposes for the reason that **`xor` expects to be attacked**.

Oh, and here's the full help text:
```
securely XOR files to STDOUT
Usage: ./bin/xor FILE...
FILE
	path to an input FILE;
	`-` means STDIN
OPTIONS
	-h
		display this text and exit
	-l
		output as many bytes as the longest
		input; for FIFO-like FILEs, output is
		infinite)
```

