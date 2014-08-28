/*	$NetBSD: manconf.h,v 1.3 2006/04/10 14:39:06 chuck Exp $	*/

/*-
 * Copyright (c) 1993
 *	The Regents of the University of California.
 * All rights reserved.
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
 *
 *	@(#)config.h	8.4 (Berkeley) 12/18/93
 */

/*
 * manconf.h: common data structures and APIs shared across all programs 
 * that access man.conf (currently: apropos, catman, makewhatis, man, and
 * whatis).
 */

/* TAG: top-level structure (one per section/reserved word) */
typedef struct _tag {
	TAILQ_ENTRY(_tag) q;			/* Queue of tags */

	TAILQ_HEAD(tqh, _entry) entrylist;	/* Queue of entries */
	char *s;				/* Associated string */
	size_t len;				/* Length of 's' */
} TAG;

/* ENTRY: each TAG has one or more ENTRY strings linked off of it */
typedef struct _entry {
	TAILQ_ENTRY(_entry) q;			/* Queue of entries */

	char *s;				/* Associated string */
	size_t len;				/* Length of 's' */
} ENTRY;

int	 addentry(TAG *, const char *, int);
void	 config(const char *);
TAG	*gettag(const char *, int);
