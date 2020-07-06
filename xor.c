/*
Copyright (C) 2020 Bailey Defino
<https://bdefino.github.io>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
securely XOR files to STDOUT

the author doesn't use the "secure" adverb lightly; vulnerabilities covered
include:
- buffer overflows (buffers are minimized),
- dynamic memory issues (double free, use-after-free, etc.) are avoided,
- format string vulnerabilities (`"%s"` protection in `*printf` functions),
- input-fueled crashes are prevented (`argc`/`argv` are untrusted),
- and barring an unknown vulnerability, at most 1 character of each input file
	is ever in primary storage (excluding caching and STDOUT)
*/

#undef PREFIX_CALLOC
#undef PREFIX_OPEN
#undef PREFIX_XOR
#undef USAGE

#define PREFIX_CALLOC		"calloc(3)"
#define PREFIX_OPEN		"open(2)"
#define PREFIX_XOR		"xor(0)"
#define USAGE			("securely XOR files to STDOUT\n" \
					"Usage: %s FILE...\n")

extern int	errno;
void *(* volatile memshred)(void *, int, size_t) = &memset;

/* return whether a file descriptor represents a FIFO-like inode */
int
isfifo(int fd)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		return -errno;
	}
	return S_ISFIFO(st.st_mode) || S_ISSOCK(st.st_mode);
}

void
usage(const char *name);

/* XOR files */
int
xor(int ofd, const int *ifds, size_t n);

int
main(int argc, const char **argv)
{
	int		*ifds;
	size_t		n;
	size_t		opened;
	const char	*prefix;
	int		retval;

	ifds = NULL;
	n = argc - 1;
	opened = 0;
	retval = 0;

	if (argc <= 1) {
		usage(argv[0]);
		retval = EXIT_FAILURE;
		goto bubble;
	}

	/* open file descriptors */

	ifds = (int *) calloc(1, n * sizeof(int));

	if (ifds == NULL) {
		prefix = PREFIX_CALLOC;
		retval = -ENOMEM;
		goto bubble;
	}
	memset(ifds, -1, n);

	for (; opened < n; opened++) {
		ifds[opened] = open(argv[opened + 1], O_RDONLY);

		if (ifds[opened] < 0) {
			prefix = PREFIX_OPEN;
			retval = -errno;
			goto bubble;
		}
	}

	/* XOR */

	prefix = PREFIX_XOR;
	retval = xor(STDOUT_FILENO, ifds, n);
bubble:
	/* close opened file descriptors */

	for (; opened > 0; close(ifds[--opened]));
	free(ifds);

	if (retval && retval < 0) {
		errno = -retval;
		perror(prefix);
	}
	return retval;
}

void
usage(const char *name)
{
	fprintf(stderr, USAGE, name);
}

int
xor(int ofd, const int *ifds, size_t n)
{
	size_t		eofsleft;
	size_t		i;
	ssize_t		iobuflen;
	struct xoristat {
		uint8_t	hiteof;
		uint8_t	isfifo;
	}		*istats;
	uint8_t		octet;
	int		retval;
	uint8_t		xored;

	retval = 0;

	if (ifds == NULL) {
		retval = -EFAULT;
		goto bubble;
	} else if (!n) {
		retval = -EINVAL;
		goto bubble;
	} else if (ofd < 0) {
		retval = -EBADF;
		goto bubble;
	}

	for (i = 0; i < n; i++) {
		if (ifds[i] < 0) {
			retval = -EBADF;
			goto bubble;
		}
	}

	/* XOR */

	istats = (struct xoristat *) calloc(1, n * sizeof(struct xoristat));

	for (i = 0; i < n; i++) {
		istats[0].isfifo = isfifo(ifds[0]);
	}

	for (eofsleft = n; eofsleft > 0; ) {
		/* XOR the next collection of octets */

		xored = 0;

		for (i = 0; i < n; i++, xored ^= octet) {
			/* read an octet */

			iobuflen = read(ifds[i], &octet, sizeof(octet));

			if (iobuflen < 0 || istats[i].isfifo) {
				retval = -errno;
				goto bubble;
			} else if (iobuflen) {
				continue;
			}

			/* EOF, and not FIFO-like: wrap around */

			if (lseek(ifds[i], 0, SEEK_SET) < 0) {
				retval = -errno;
				goto bubble;
			}
			iobuflen = read(ifds[i], &octet, sizeof(octet));

			if (iobuflen != sizeof(octet)) {
				retval = -errno;
				goto bubble;
			}
			eofsleft -= istats[i].hiteof ? 0 : 1;
			istats[i].hiteof = ~0;
		}

		if (!eofsleft) {
			break;
		}

		if (write(ofd, &xored, sizeof(xored)) != sizeof(xored)) {
			retval = errno ? -errno : -EIO;
			goto bubble;
		}
	}
bubble:
	/* shred cryptographic remnants */

	memshred(&xored, '\0', sizeof(xored));
	memshred(&octet, '\0', sizeof(octet));

	memshred(istats, '\0', n * sizeof(struct xoristat));
	free(istats);
	return retval;
}

