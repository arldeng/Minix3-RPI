/*	$NetBSD: util.c,v 1.12 2005/02/17 17:09:48 xtraeme Exp $	*/

/*-
 * Copyright (c) 1988, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#ifndef lint
#if 0
static char sccsid[] = "@(#)util.c	8.4 (Berkeley) 4/2/94";
#else
__RCSID("$NetBSD: util.c,v 1.12 2005/02/17 17:09:48 xtraeme Exp $");
#endif
#endif /* not lint */

#include <sys/types.h>

#include <ctype.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tzfile.h>
#include <unistd.h>

#include "chpass.h"
#include "pathnames.h"

char *
ttoa(char *buf, size_t len, time_t tval)
{

	if (tval) {
		struct tm *tp = localtime(&tval);

		(void) strftime(buf, len, "%B %d, %Y", tp);
		buf[len - 1] = '\0';
	}
	else if (len > 0)
		*buf = '\0';
	return (buf);
} 

int
atot(const char *p, time_t *store)
{
	static struct tm *lt;
	struct tm tm;
	char *t;
	time_t tval;

	if (!*p) {
		*store = 0;
		return (0);
	}
	if (!lt) {
		unsetenv("TZ");
		(void)time(&tval);
		lt = localtime(&tval);
	}
	(void) memset(&tm, 0, sizeof(tm));
	while ((t = strchr(p, ',')) != NULL)
		*t = ' ';
	t = strptime(p, "%B %d %Y", &tm);
	if (t == NULL || (*t != '\0' && *t != '\n'))
		return 1;
	if ((*store = mktime(&tm)) == (time_t) -1)
		return 1;
	return (0);
}

const char *
ok_shell(const char *name)
{
	char *p;
	const char *sh;

	setusershell();
	while ((sh = getusershell()) != NULL) {
		if (!strcmp(name, sh))
			return (name);
		/* allow just shell name, but use "real" path */
		if ((p = strrchr(sh, '/')) && strcmp(name, p + 1) == 0)
			return (sh);
	}
	return (NULL);
}
