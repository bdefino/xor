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
#include <getopt.h>
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
*//************************************************
- buflen option?
- change to bitwise utility?
- internal offset options?
*************************************************/

#undef HELP
#undef OPTSTRING
#undef PATH_STDIN
#undef PREFIX_CALLOC
#undef PREFIX_GETOPT
#undef PREFIX_OPEN
#undef PREFIX_XOR
#undef USAGE

#define HELP		("FILE\n" \
				"\tpath to an input FILE;\n" \
				"\t`-` means STDIN\n" \
				"OPTIONS\n" \
				"\t-h\n" \
				"\t\tdisplay this text and exit\n" \
				"\t-l\n" \
				"\t\toutput as many bytes as the longest\n" \
				"\t\tinput; for FIFO-like FILEs, output is\n" \
				"\t\tinfinite)\n")
#define OPTSTRING	"hl+"
#define PATH_STDIN	"-"
#define PREFIX_CALLOC	"calloc(3)"
#define PREFIX_GETOPT	"getopt(3)"
#define PREFIX_OPEN	"open(2)"
#define PREFIX_XOR	"xor(0)"
#define USAGE		("securely XOR files to STDOUT\n" \
				"Usage: %s FILE...\n")

/* flags */

#undef XOR_FLAG_LONGEST

#define XOR_FLAG_LONGEST	0x1

extern int	errno;
void *(* volatile memshred)(void *, int, size_t) = &memset;

void
usage(const char *name);

void
help(const char *name)
{
	usage(name);
	fprintf(stderr, "%s", HELP);
}

/* XOR files */
int
xor(int ofd, int flags, const int *ifds, size_t n);

int
main(int argc, const char **argv)
{
	int		c;
	int		flags;
	int		*ifds;
	size_t		n;
	size_t		opened;
	const char	*path;
	const char	*prefix;
	int		retval;

	flags = 0;
	ifds = NULL;
	n = 0;
	opened = 0;
	prefix = NULL;
	retval = 0;

	/* parse arguments */

	if (argc <= 1) {
		usage(argv[0]);
		retval = EXIT_FAILURE;
		goto bubble;
	}

	for (c = 0; c >= 0; ) {
		c = getopt(argc, (char **) argv, OPTSTRING);

		switch (c) {
		case -1:
			break;
		case ':':
		case '?':
			prefix = PREFIX_GETOPT;
			retval = EXIT_FAILURE;
			goto bubble;
		case 'h':
			help(argv[0]);
			goto bubble;
		case 'l':
			flags |= XOR_FLAG_LONGEST;
			break;
		default:
			prefix = PREFIX_GETOPT;
			retval = EXIT_FAILURE;
			goto bubble;
		}
	}
	n = argc - optind;

	/* open file descriptors */

	ifds = (int *) calloc(1, n * sizeof(int));

	if (ifds == NULL) {
		prefix = PREFIX_CALLOC;
		retval = -ENOMEM;
		goto bubble;
	}
	memset(ifds, -1, n);

	for (; opened < n; opened++) {
		path = argv[opened + optind];

		ifds[opened] = strcmp(path, PATH_STDIN)
			? open(argv[opened + optind], O_RDONLY) : STDIN_FILENO;

		if (ifds[opened] < 0) {
			prefix = PREFIX_OPEN;
			retval = -errno;
			goto bubble;
		}
	}

	/* XOR */

	prefix = PREFIX_XOR;
	retval = xor(STDOUT_FILENO, flags, ifds, n);
bubble:
	/* close opened file descriptors */

	while (opened-- > 0) {
		if (ifds[opened] != STDIN_FILENO) {
			close(ifds[opened]);
		}
	}
	free(ifds);

	if (retval < 0) {
		errno = -retval;
		perror(prefix);
	} else if (retval && prefix != NULL) {
		fprintf(stderr, "%s: error\n", prefix);
	}
	return retval;
}

void
usage(const char *name)
{
	fprintf(stderr, USAGE, name);
}

int
xor(int ofd, int flags, const int *ifds, size_t n)
{
	size_t			eofsleft;
	size_t			i;
	ssize_t			iobuflen;
	struct stat		istat;
	struct xoristat {
		uint8_t		fifolike;
		uint8_t		hiteof;
	}			*istats;
	uint8_t			octet;
	int			retval;
	uint8_t			xored;

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
		if (fstat(ifds[i], &istat)) {
			retval = -errno;
			goto bubble;
		}
		istats[i].fifolike = !S_ISBLK(istat.st_mode)
			&& !S_ISDIR(istat.st_mode) && !S_ISREG(istat.st_mode);
	}

	for (eofsleft = n; eofsleft > 0; ) {
		/* XOR the next collection of octets */

		xored = 0;

		for (i = 0; i < n; i++, xored ^= octet) {
			/* read an octet */

			iobuflen = read(ifds[i], &octet, sizeof(octet));

			if (iobuflen < 0 || istats[i].fifolike) {
				retval = -errno;
				goto bubble;
			} else if (iobuflen) {
				continue;
			} else if (!iobuflen && !(flags & XOR_FLAG_LONGEST)) {
				/* stop */

				goto bubble;
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

