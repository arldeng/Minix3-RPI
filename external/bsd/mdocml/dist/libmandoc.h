/*	$Vendor-Id: libmandoc.h,v 1.10 2011/01/03 22:42:37 schwarze Exp $ */
/*
 * Copyright (c) 2009, 2010 Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifndef LIBMANDOC_H
#define LIBMANDOC_H

__BEGIN_DECLS

int		 mandoc_special(char *);
void		*mandoc_calloc(size_t, size_t);
char		*mandoc_strdup(const char *);
void		*mandoc_malloc(size_t);
void		*mandoc_realloc(void *, size_t);
char		*mandoc_getarg(char **, mandocmsg, void *, int, int *);
time_t		 mandoc_a2time(int, const char *);
#define		 MTIME_CANONICAL	(1 << 0)
#define		 MTIME_REDUCED		(1 << 1)
#define		 MTIME_MDOCDATE		(1 << 2)
#define		 MTIME_ISO_8601		(1 << 3)
int		 mandoc_eos(const char *, size_t, int);
int		 mandoc_hyph(const char *, const char *);

__END_DECLS

#endif /*!LIBMANDOC_H*/
