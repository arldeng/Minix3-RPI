/*	$Vendor-Id: man.c,v 1.96 2011/01/03 11:31:26 kristaps Exp $ */
/*
 * Copyright (c) 2008, 2009, 2010 Kristaps Dzonsons <kristaps@bsd.lv>
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#include <assert.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mandoc.h"
#include "libman.h"
#include "libmandoc.h"

const	char *const __man_macronames[MAN_MAX] = {		 
	"br",		"TH",		"SH",		"SS",
	"TP", 		"LP",		"PP",		"P",
	"IP",		"HP",		"SM",		"SB",
	"BI",		"IB",		"BR",		"RB",
	"R",		"B",		"I",		"IR",
	"RI",		"na",		"sp",		"nf",
	"fi",		"RE",		"RS",		"DT",
	"UC",		"PD",		"AT",		"in",
	"ft"
	};

const	char * const *man_macronames = __man_macronames;

static	struct man_node	*man_node_alloc(int, int, 
				enum man_type, enum mant);
static	int		 man_node_append(struct man *, 
				struct man_node *);
static	int		 man_span_alloc(struct man *, 
				const struct tbl_span *);
static	void		 man_node_free(struct man_node *);
static	void		 man_node_unlink(struct man *, 
				struct man_node *);
static	int		 man_ptext(struct man *, int, char *, int);
static	int		 man_pmacro(struct man *, int, char *, int);
static	void		 man_free1(struct man *);
static	void		 man_alloc1(struct man *);
static	int		 man_descope(struct man *, int, int);


const struct man_node *
man_node(const struct man *m)
{

	assert( ! (MAN_HALT & m->flags));
	return(m->first);
}


const struct man_meta *
man_meta(const struct man *m)
{

	assert( ! (MAN_HALT & m->flags));
	return(&m->meta);
}


void
man_reset(struct man *man)
{

	man_free1(man);
	man_alloc1(man);
}


void
man_free(struct man *man)
{

	man_free1(man);
	free(man);
}


struct man *
man_alloc(struct regset *regs, void *data, mandocmsg msg)
{
	struct man	*p;

	p = mandoc_calloc(1, sizeof(struct man));

	man_hash_init();
	p->data = data;
	p->msg = msg;
	p->regs = regs;

	man_alloc1(p);
	return(p);
}


int
man_endparse(struct man *m)
{

	assert( ! (MAN_HALT & m->flags));
	if (man_macroend(m))
		return(1);
	m->flags |= MAN_HALT;
	return(0);
}


int
man_parseln(struct man *m, int ln, char *buf, int offs)
{

	assert( ! (MAN_HALT & m->flags));
	return(('.' == buf[offs] || '\'' == buf[offs]) ? 
			man_pmacro(m, ln, buf, offs) : 
			man_ptext(m, ln, buf, offs));
}


static void
man_free1(struct man *man)
{

	if (man->first)
		man_node_delete(man, man->first);
	if (man->meta.title)
		free(man->meta.title);
	if (man->meta.source)
		free(man->meta.source);
	if (man->meta.rawdate)
		free(man->meta.rawdate);
	if (man->meta.vol)
		free(man->meta.vol);
	if (man->meta.msec)
		free(man->meta.msec);
}


static void
man_alloc1(struct man *m)
{

	memset(&m->meta, 0, sizeof(struct man_meta));
	m->flags = 0;
	m->last = mandoc_calloc(1, sizeof(struct man_node));
	m->first = m->last;
	m->last->type = MAN_ROOT;
	m->last->tok = MAN_MAX;
	m->next = MAN_NEXT_CHILD;
}


static int
man_node_append(struct man *man, struct man_node *p)
{

	assert(man->last);
	assert(man->first);
	assert(MAN_ROOT != p->type);

	switch (man->next) {
	case (MAN_NEXT_SIBLING):
		man->last->next = p;
		p->prev = man->last;
		p->parent = man->last->parent;
		break;
	case (MAN_NEXT_CHILD):
		man->last->child = p;
		p->parent = man->last;
		break;
	default:
		abort();
		/* NOTREACHED */
	}
	
	assert(p->parent);
	p->parent->nchild++;

	if ( ! man_valid_pre(man, p))
		return(0);

	switch (p->type) {
	case (MAN_HEAD):
		assert(MAN_BLOCK == p->parent->type);
		p->parent->head = p;
		break;
	case (MAN_BODY):
		assert(MAN_BLOCK == p->parent->type);
		p->parent->body = p;
		break;
	default:
		break;
	}

	man->last = p;

	switch (p->type) {
	case (MAN_TBL):
		/* FALLTHROUGH */
	case (MAN_TEXT):
		if ( ! man_valid_post(man))
			return(0);
		break;
	default:
		break;
	}

	return(1);
}


static struct man_node *
man_node_alloc(int line, int pos, enum man_type type, enum mant tok)
{
	struct man_node *p;

	p = mandoc_calloc(1, sizeof(struct man_node));
	p->line = line;
	p->pos = pos;
	p->type = type;
	p->tok = tok;
	return(p);
}


int
man_elem_alloc(struct man *m, int line, int pos, enum mant tok)
{
	struct man_node *p;

	p = man_node_alloc(line, pos, MAN_ELEM, tok);
	if ( ! man_node_append(m, p))
		return(0);
	m->next = MAN_NEXT_CHILD;
	return(1);
}


int
man_head_alloc(struct man *m, int line, int pos, enum mant tok)
{
	struct man_node *p;

	p = man_node_alloc(line, pos, MAN_HEAD, tok);
	if ( ! man_node_append(m, p))
		return(0);
	m->next = MAN_NEXT_CHILD;
	return(1);
}


int
man_body_alloc(struct man *m, int line, int pos, enum mant tok)
{
	struct man_node *p;

	p = man_node_alloc(line, pos, MAN_BODY, tok);
	if ( ! man_node_append(m, p))
		return(0);
	m->next = MAN_NEXT_CHILD;
	return(1);
}


int
man_block_alloc(struct man *m, int line, int pos, enum mant tok)
{
	struct man_node *p;

	p = man_node_alloc(line, pos, MAN_BLOCK, tok);
	if ( ! man_node_append(m, p))
		return(0);
	m->next = MAN_NEXT_CHILD;
	return(1);
}

static int
man_span_alloc(struct man *m, const struct tbl_span *span)
{
	struct man_node	*n;

	/* FIXME: grab from span */
	n = man_node_alloc(0, 0, MAN_TBL, MAN_MAX);
	n->span = span;

	if ( ! man_node_append(m, n))
		return(0);

	m->next = MAN_NEXT_SIBLING;
	return(1);
}

int
man_word_alloc(struct man *m, int line, int pos, const char *word)
{
	struct man_node	*n;
	size_t		 sv, len;

	len = strlen(word);

	n = man_node_alloc(line, pos, MAN_TEXT, MAN_MAX);
	n->string = mandoc_malloc(len + 1);
	sv = strlcpy(n->string, word, len + 1);

	/* Prohibit truncation. */
	assert(sv < len + 1);

	if ( ! man_node_append(m, n))
		return(0);

	m->next = MAN_NEXT_SIBLING;
	return(1);
}


/*
 * Free all of the resources held by a node.  This does NOT unlink a
 * node from its context; for that, see man_node_unlink().
 */
static void
man_node_free(struct man_node *p)
{

	if (p->string)
		free(p->string);
	free(p);
}


void
man_node_delete(struct man *m, struct man_node *p)
{

	while (p->child)
		man_node_delete(m, p->child);

	man_node_unlink(m, p);
	man_node_free(p);
}


int
man_addspan(struct man *m, const struct tbl_span *sp)
{

	assert( ! (MAN_HALT & m->flags));
	if ( ! man_span_alloc(m, sp))
		return(0);
	return(man_descope(m, 0, 0));
}

static int
man_descope(struct man *m, int line, int offs)
{
	/*
	 * Co-ordinate what happens with having a next-line scope open:
	 * first close out the element scope (if applicable), then close
	 * out the block scope (also if applicable).
	 */

	if (MAN_ELINE & m->flags) {
		m->flags &= ~MAN_ELINE;
		if ( ! man_unscope(m, m->last->parent, MANDOCERR_MAX))
			return(0);
	}

	if ( ! (MAN_BLINE & m->flags))
		return(1);
	m->flags &= ~MAN_BLINE;

	if ( ! man_unscope(m, m->last->parent, MANDOCERR_MAX))
		return(0);
	return(man_body_alloc(m, line, offs, m->last->tok));
}


static int
man_ptext(struct man *m, int line, char *buf, int offs)
{
	int		 i;

	/* Ignore bogus comments. */

	if ('\\' == buf[offs] && 
			'.' == buf[offs + 1] && 
			'"' == buf[offs + 2]) {
		man_pmsg(m, line, offs, MANDOCERR_BADCOMMENT);
		return(1);
	}

	/* Literal free-form text whitespace is preserved. */

	if (MAN_LITERAL & m->flags) {
		if ( ! man_word_alloc(m, line, offs, buf + offs))
			return(0);
		return(man_descope(m, line, offs));
	}

	/* Pump blank lines directly into the backend. */

	for (i = offs; ' ' == buf[i]; i++)
		/* Skip leading whitespace. */ ;

	if ('\0' == buf[i]) {
		/* Allocate a blank entry. */
		if ( ! man_word_alloc(m, line, offs, ""))
			return(0);
		return(man_descope(m, line, offs));
	}

	/* 
	 * Warn if the last un-escaped character is whitespace. Then
	 * strip away the remaining spaces (tabs stay!).   
	 */

	i = (int)strlen(buf);
	assert(i);

	if (' ' == buf[i - 1] || '\t' == buf[i - 1]) {
		if (i > 1 && '\\' != buf[i - 2])
			man_pmsg(m, line, i - 1, MANDOCERR_EOLNSPACE);

		for (--i; i && ' ' == buf[i]; i--)
			/* Spin back to non-space. */ ;

		/* Jump ahead of escaped whitespace. */
		i += '\\' == buf[i] ? 2 : 1;

		buf[i] = '\0';
	}

	if ( ! man_word_alloc(m, line, offs, buf + offs))
		return(0);

	/*
	 * End-of-sentence check.  If the last character is an unescaped
	 * EOS character, then flag the node as being the end of a
	 * sentence.  The front-end will know how to interpret this.
	 */

	assert(i);
	if (mandoc_eos(buf, (size_t)i, 0))
		m->last->flags |= MAN_EOS;

	return(man_descope(m, line, offs));
}


static int
man_pmacro(struct man *m, int ln, char *buf, int offs)
{
	int		 i, j, ppos;
	enum mant	 tok;
	char		 mac[5];
	struct man_node	*n;

	/* Comments and empties are quickly ignored. */

	offs++;

	if ('\0' == buf[offs])
		return(1);

	i = offs;

	/*
	 * Skip whitespace between the control character and initial
	 * text.  "Whitespace" is both spaces and tabs.
	 */

	if (' ' == buf[i] || '\t' == buf[i]) {
		i++;
		while (buf[i] && (' ' == buf[i] || '\t' == buf[i]))
			i++;
		if ('\0' == buf[i])
			goto out;
	}

	ppos = i;

	/*
	 * Copy the first word into a nil-terminated buffer.
	 * Stop copying when a tab, space, or eoln is encountered.
	 */

	j = 0;
	while (j < 4 && '\0' != buf[i] && ' ' != buf[i] && '\t' != buf[i])
		mac[j++] = buf[i++];
	mac[j] = '\0';

	tok = (j > 0 && j < 4) ? man_hash_find(mac) : MAN_MAX;
	if (MAN_MAX == tok) {
		man_vmsg(m, MANDOCERR_MACRO, ln, ppos, "%s", buf + ppos - 1);
		return(1);
	}

	/* The macro is sane.  Jump to the next word. */

	while (buf[i] && ' ' == buf[i])
		i++;

	/* 
	 * Trailing whitespace.  Note that tabs are allowed to be passed
	 * into the parser as "text", so we only warn about spaces here.
	 */

	if ('\0' == buf[i] && ' ' == buf[i - 1])
		man_pmsg(m, ln, i - 1, MANDOCERR_EOLNSPACE);

	/* 
	 * Remove prior ELINE macro, as it's being clobbered by a new
	 * macro.  Note that NSCOPED macros do not close out ELINE
	 * macros---they don't print text---so we let those slip by.
	 */

	if ( ! (MAN_NSCOPED & man_macros[tok].flags) &&
			m->flags & MAN_ELINE) {
		n = m->last;
		assert(MAN_TEXT != n->type);

		/* Remove repeated NSCOPED macros causing ELINE. */

		if (MAN_NSCOPED & man_macros[n->tok].flags)
			n = n->parent;

		man_vmsg(m, MANDOCERR_LINESCOPE, n->line, n->pos,
				"%s", man_macronames[n->tok]);

		man_node_delete(m, n);
		m->flags &= ~MAN_ELINE;
	}

	/*
	 * Save the fact that we're in the next-line for a block.  In
	 * this way, embedded roff instructions can "remember" state
	 * when they exit.
	 */

	if (MAN_BLINE & m->flags)
		m->flags |= MAN_BPLINE;

	/* Call to handler... */

	assert(man_macros[tok].fp);
	if ( ! (*man_macros[tok].fp)(m, tok, ln, ppos, &i, buf))
		goto err;

out:
	/* 
	 * We weren't in a block-line scope when entering the
	 * above-parsed macro, so return.
	 */

	if ( ! (MAN_BPLINE & m->flags)) {
		m->flags &= ~MAN_ILINE; 
		return(1);
	}
	m->flags &= ~MAN_BPLINE;

	/*
	 * If we're in a block scope, then allow this macro to slip by
	 * without closing scope around it.
	 */

	if (MAN_ILINE & m->flags) {
		m->flags &= ~MAN_ILINE;
		return(1);
	}

	/* 
	 * If we've opened a new next-line element scope, then return
	 * now, as the next line will close out the block scope.
	 */

	if (MAN_ELINE & m->flags)
		return(1);

	/* Close out the block scope opened in the prior line.  */

	assert(MAN_BLINE & m->flags);
	m->flags &= ~MAN_BLINE;

	if ( ! man_unscope(m, m->last->parent, MANDOCERR_MAX))
		return(0);
	return(man_body_alloc(m, ln, offs, m->last->tok));

err:	/* Error out. */

	m->flags |= MAN_HALT;
	return(0);
}


int
man_vmsg(struct man *man, enum mandocerr t, 
		int ln, int pos, const char *fmt, ...)
{
	char		 buf[256];
	va_list		 ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	return((*man->msg)(t, man->data, ln, pos, buf));
}


/*
 * Unlink a node from its context.  If "m" is provided, the last parse
 * point will also be adjusted accordingly.
 */
static void
man_node_unlink(struct man *m, struct man_node *n)
{

	/* Adjust siblings. */

	if (n->prev)
		n->prev->next = n->next;
	if (n->next)
		n->next->prev = n->prev;

	/* Adjust parent. */

	if (n->parent) {
		n->parent->nchild--;
		if (n->parent->child == n)
			n->parent->child = n->prev ? n->prev : n->next;
	}

	/* Adjust parse point, if applicable. */

	if (m && m->last == n) {
		/*XXX: this can occur when bailing from validation. */
		/*assert(NULL == n->next);*/
		if (n->prev) {
			m->last = n->prev;
			m->next = MAN_NEXT_SIBLING;
		} else {
			m->last = n->parent;
			m->next = MAN_NEXT_CHILD;
		}
	}

	if (m && m->first == n)
		m->first = NULL;
}
