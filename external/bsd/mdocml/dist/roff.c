/*	$Vendor-Id: roff.c,v 1.120 2011/01/03 23:24:16 schwarze Exp $ */
/*
 * Copyright (c) 2010, 2011 Kristaps Dzonsons <kristaps@bsd.lv>
 * Copyright (c) 2010, 2011 Ingo Schwarze <schwarze@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mandoc.h"
#include "roff.h"
#include "libroff.h"
#include "libmandoc.h"

#define	RSTACK_MAX	128

#define	ROFF_CTL(c) \
	('.' == (c) || '\'' == (c))

enum	rofft {
	ROFF_ad,
	ROFF_am,
	ROFF_ami,
	ROFF_am1,
	ROFF_de,
	ROFF_dei,
	ROFF_de1,
	ROFF_ds,
	ROFF_el,
	ROFF_hy,
	ROFF_ie,
	ROFF_if,
	ROFF_ig,
	ROFF_ne,
	ROFF_nh,
	ROFF_nr,
	ROFF_rm,
	ROFF_so,
	ROFF_tr,
	ROFF_TS,
	ROFF_TE,
	ROFF_T_,
	ROFF_cblock,
	ROFF_ccond, /* FIXME: remove this. */
	ROFF_USERDEF,
	ROFF_MAX
};

enum	roffrule {
	ROFFRULE_ALLOW,
	ROFFRULE_DENY
};

struct	roffstr {
	char		*name; /* key of symbol */
	char		*string; /* current value */
	struct roffstr	*next; /* next in list */
};

struct	roff {
	struct roffnode	*last; /* leaf of stack */
	mandocmsg	 msg; /* err/warn/fatal messages */
	void		*data; /* privdata for messages */
	enum roffrule	 rstack[RSTACK_MAX]; /* stack of !`ie' rules */
	int		 rstackpos; /* position in rstack */
	struct regset	*regs; /* read/writable registers */
	struct roffstr	*first_string; /* user-defined strings & macros */
	const char	*current_string; /* value of last called user macro */
	struct tbl_node	*first_tbl; /* first table parsed */
	struct tbl_node	*last_tbl; /* last table parsed */
	struct tbl_node	*tbl; /* current table being parsed */
};

struct	roffnode {
	enum rofft	 tok; /* type of node */
	struct roffnode	*parent; /* up one in stack */
	int		 line; /* parse line */
	int		 col; /* parse col */
	char		*name; /* node name, e.g. macro name */
	char		*end; /* end-rules: custom token */
	int		 endspan; /* end-rules: next-line or infty */
	enum roffrule	 rule; /* current evaluation rule */
};

#define	ROFF_ARGS	 struct roff *r, /* parse ctx */ \
			 enum rofft tok, /* tok of macro */ \
		 	 char **bufp, /* input buffer */ \
			 size_t *szp, /* size of input buffer */ \
			 int ln, /* parse line */ \
			 int ppos, /* original pos in buffer */ \
			 int pos, /* current pos in buffer */ \
			 int *offs /* reset offset of buffer data */

typedef	enum rofferr (*roffproc)(ROFF_ARGS);

struct	roffmac {
	const char	*name; /* macro name */
	roffproc	 proc; /* process new macro */
	roffproc	 text; /* process as child text of macro */
	roffproc	 sub; /* process as child of macro */
	int		 flags;
#define	ROFFMAC_STRUCT	(1 << 0) /* always interpret */
	struct roffmac	*next;
};

static	enum rofferr	 roff_block(ROFF_ARGS);
static	enum rofferr	 roff_block_text(ROFF_ARGS);
static	enum rofferr	 roff_block_sub(ROFF_ARGS);
static	enum rofferr	 roff_cblock(ROFF_ARGS);
static	enum rofferr	 roff_ccond(ROFF_ARGS);
static	enum rofferr	 roff_cond(ROFF_ARGS);
static	enum rofferr	 roff_cond_text(ROFF_ARGS);
static	enum rofferr	 roff_cond_sub(ROFF_ARGS);
static	enum rofferr	 roff_ds(ROFF_ARGS);
static	enum roffrule	 roff_evalcond(const char *, int *);
static	void		 roff_freestr(struct roff *);
static	const char	*roff_getstrn(const struct roff *, 
				const char *, size_t);
static	enum rofferr	 roff_line_ignore(ROFF_ARGS);
static	enum rofferr	 roff_line_error(ROFF_ARGS);
static	enum rofferr	 roff_nr(ROFF_ARGS);
static	int		 roff_res(struct roff *, 
				char **, size_t *, int);
static	void		 roff_setstr(struct roff *,
				const char *, const char *, int);
static	enum rofferr	 roff_so(ROFF_ARGS);
static	enum rofferr	 roff_TE(ROFF_ARGS);
static	enum rofferr	 roff_TS(ROFF_ARGS);
static	enum rofferr	 roff_T_(ROFF_ARGS);
static	enum rofferr	 roff_userdef(ROFF_ARGS);

/* See roff_hash_find() */

#define	ASCII_HI	 126
#define	ASCII_LO	 33
#define	HASHWIDTH	(ASCII_HI - ASCII_LO + 1)

static	struct roffmac	*hash[HASHWIDTH];

static	struct roffmac	 roffs[ROFF_MAX] = {
	{ "ad", roff_line_ignore, NULL, NULL, 0, NULL },
	{ "am", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "ami", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "am1", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "de", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "dei", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "de1", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "ds", roff_ds, NULL, NULL, 0, NULL },
	{ "el", roff_cond, roff_cond_text, roff_cond_sub, ROFFMAC_STRUCT, NULL },
	{ "hy", roff_line_ignore, NULL, NULL, 0, NULL },
	{ "ie", roff_cond, roff_cond_text, roff_cond_sub, ROFFMAC_STRUCT, NULL },
	{ "if", roff_cond, roff_cond_text, roff_cond_sub, ROFFMAC_STRUCT, NULL },
	{ "ig", roff_block, roff_block_text, roff_block_sub, 0, NULL },
	{ "ne", roff_line_ignore, NULL, NULL, 0, NULL },
	{ "nh", roff_line_ignore, NULL, NULL, 0, NULL },
	{ "nr", roff_nr, NULL, NULL, 0, NULL },
	{ "rm", roff_line_error, NULL, NULL, 0, NULL },
	{ "so", roff_so, NULL, NULL, 0, NULL },
	{ "tr", roff_line_ignore, NULL, NULL, 0, NULL },
	{ "TS", roff_TS, NULL, NULL, 0, NULL },
	{ "TE", roff_TE, NULL, NULL, 0, NULL },
	{ "T&", roff_T_, NULL, NULL, 0, NULL },
	{ ".", roff_cblock, NULL, NULL, 0, NULL },
	{ "\\}", roff_ccond, NULL, NULL, 0, NULL },
	{ NULL, roff_userdef, NULL, NULL, 0, NULL },
};

static	void		 roff_free1(struct roff *);
static	enum rofft	 roff_hash_find(const char *, size_t);
static	void		 roff_hash_init(void);
static	void		 roffnode_cleanscope(struct roff *);
static	void		 roffnode_push(struct roff *, enum rofft,
				const char *, int, int);
static	void		 roffnode_pop(struct roff *);
static	enum rofft	 roff_parse(struct roff *, const char *, int *);
static	int		 roff_parse_nat(const char *, unsigned int *);

/* See roff_hash_find() */
#define	ROFF_HASH(p)	(p[0] - ASCII_LO)

static void
roff_hash_init(void)
{
	struct roffmac	 *n;
	int		  buc, i;

	for (i = 0; i < (int)ROFF_USERDEF; i++) {
		assert(roffs[i].name[0] >= ASCII_LO);
		assert(roffs[i].name[0] <= ASCII_HI);

		buc = ROFF_HASH(roffs[i].name);

		if (NULL != (n = hash[buc])) {
			for ( ; n->next; n = n->next)
				/* Do nothing. */ ;
			n->next = &roffs[i];
		} else
			hash[buc] = &roffs[i];
	}
}


/*
 * Look up a roff token by its name.  Returns ROFF_MAX if no macro by
 * the nil-terminated string name could be found.
 */
static enum rofft
roff_hash_find(const char *p, size_t s)
{
	int		 buc;
	struct roffmac	*n;

	/*
	 * libroff has an extremely simple hashtable, for the time
	 * being, which simply keys on the first character, which must
	 * be printable, then walks a chain.  It works well enough until
	 * optimised.
	 */

	if (p[0] < ASCII_LO || p[0] > ASCII_HI)
		return(ROFF_MAX);

	buc = ROFF_HASH(p);

	if (NULL == (n = hash[buc]))
		return(ROFF_MAX);
	for ( ; n; n = n->next)
		if (0 == strncmp(n->name, p, s) && '\0' == n->name[(int)s])
			return((enum rofft)(n - roffs));

	return(ROFF_MAX);
}


/*
 * Pop the current node off of the stack of roff instructions currently
 * pending.
 */
static void
roffnode_pop(struct roff *r)
{
	struct roffnode	*p;

	assert(r->last);
	p = r->last; 

	if (ROFF_el == p->tok)
		if (r->rstackpos > -1)
			r->rstackpos--;

	r->last = r->last->parent;
	free(p->name);
	free(p->end);
	free(p);
}


/*
 * Push a roff node onto the instruction stack.  This must later be
 * removed with roffnode_pop().
 */
static void
roffnode_push(struct roff *r, enum rofft tok, const char *name,
		int line, int col)
{
	struct roffnode	*p;

	p = mandoc_calloc(1, sizeof(struct roffnode));
	p->tok = tok;
	if (name)
		p->name = mandoc_strdup(name);
	p->parent = r->last;
	p->line = line;
	p->col = col;
	p->rule = p->parent ? p->parent->rule : ROFFRULE_DENY;

	r->last = p;
}


static void
roff_free1(struct roff *r)
{
	struct tbl_node	*t;

	while (r->first_tbl) {
		t = r->first_tbl;
		r->first_tbl = t->next;
		tbl_free(t);
	}

	r->first_tbl = r->last_tbl = r->tbl = NULL;

	while (r->last)
		roffnode_pop(r);

	roff_freestr(r);
}


void
roff_reset(struct roff *r)
{

	roff_free1(r);
}


void
roff_free(struct roff *r)
{

	roff_free1(r);
	free(r);
}


struct roff *
roff_alloc(struct regset *regs, void *data, const mandocmsg msg)
{
	struct roff	*r;

	r = mandoc_calloc(1, sizeof(struct roff));
	r->regs = regs;
	r->msg = msg;
	r->data = data;
	r->rstackpos = -1;
	
	roff_hash_init();
	return(r);
}


/*
 * Pre-filter each and every line for reserved words (one beginning with
 * `\*', e.g., `\*(ab').  These must be handled before the actual line
 * is processed. 
 */
static int
roff_res(struct roff *r, char **bufp, size_t *szp, int pos)
{
	const char	*stesc;	/* start of an escape sequence ('\\') */
	const char	*stnam;	/* start of the name, after "[(*" */
	const char	*cp;	/* end of the name, e.g. before ']' */
	const char	*res;	/* the string to be substituted */
	int		 i, maxl;
	size_t		 nsz;
	char		*n;

	/* Search for a leading backslash and save a pointer to it. */

	cp = *bufp + pos;
	while (NULL != (cp = strchr(cp, '\\'))) {
		stesc = cp++;

		/*
		 * The second character must be an asterisk.
		 * If it isn't, skip it anyway:  It is escaped,
		 * so it can't start another escape sequence.
		 */

		if ('\0' == *cp)
			return(1);
		if ('*' != *cp++)
			continue;

		/*
		 * The third character decides the length
		 * of the name of the string.
		 * Save a pointer to the name.
		 */

		switch (*cp) {
		case ('\0'):
			return(1);
		case ('('):
			cp++;
			maxl = 2;
			break;
		case ('['):
			cp++;
			maxl = 0;
			break;
		default:
			maxl = 1;
			break;
		}
		stnam = cp;

		/* Advance to the end of the name. */

		for (i = 0; 0 == maxl || i < maxl; i++, cp++) {
			if ('\0' == *cp)
				return(1); /* Error. */
			if (0 == maxl && ']' == *cp)
				break;
		}

		/*
		 * Retrieve the replacement string; if it is
		 * undefined, resume searching for escapes.
		 */

		res = roff_getstrn(r, stnam, (size_t)i);

		if (NULL == res) {
			cp -= maxl ? 1 : 0;
			continue;
		}

		/* Replace the escape sequence by the string. */

		nsz = *szp + strlen(res) + 1;
		n = mandoc_malloc(nsz);

		strlcpy(n, *bufp, (size_t)(stesc - *bufp + 1));
		strlcat(n, res, nsz);
		strlcat(n, cp + (maxl ? 0 : 1), nsz);

		free(*bufp);

		*bufp = n;
		*szp = nsz;
		return(0);
	}

	return(1);
}


enum rofferr
roff_parseln(struct roff *r, int ln, char **bufp, 
		size_t *szp, int pos, int *offs)
{
	enum rofft	 t;
	enum rofferr	 e;
	int		 ppos;

	/*
	 * Run the reserved-word filter only if we have some reserved
	 * words to fill in.
	 */

	if (r->first_string && ! roff_res(r, bufp, szp, pos))
		return(ROFF_REPARSE);

	/*
	 * First, if a scope is open and we're not a macro, pass the
	 * text through the macro's filter.  If a scope isn't open and
	 * we're not a macro, just let it through.
	 */

	if (r->last && ! ROFF_CTL((*bufp)[pos])) {
		t = r->last->tok;
		assert(roffs[t].text);
		e = (*roffs[t].text)
			(r, t, bufp, szp, ln, pos, pos, offs);
		assert(ROFF_IGN == e || ROFF_CONT == e);
		if (ROFF_CONT == e && r->tbl)
			return(tbl_read(r->tbl, ln, *bufp, *offs));
		return(e);
	} else if ( ! ROFF_CTL((*bufp)[pos])) {
		if (r->tbl)
			return(tbl_read(r->tbl, ln, *bufp, *offs));
		return(ROFF_CONT);
	}

	/*
	 * If a scope is open, go to the child handler for that macro,
	 * as it may want to preprocess before doing anything with it.
	 */

	if (r->last) {
		t = r->last->tok;
		assert(roffs[t].sub);
		return((*roffs[t].sub)
				(r, t, bufp, szp, 
				 ln, pos, pos, offs));
	}

	/*
	 * Lastly, as we've no scope open, try to look up and execute
	 * the new macro.  If no macro is found, simply return and let
	 * the compilers handle it.
	 */

	ppos = pos;
	if (ROFF_MAX == (t = roff_parse(r, *bufp, &pos)))
		return(ROFF_CONT);

	assert(roffs[t].proc);
	return((*roffs[t].proc)
			(r, t, bufp, szp, 
			 ln, ppos, pos, offs));
}


void
roff_endparse(struct roff *r)
{

	if (r->last)
		(*r->msg)(MANDOCERR_SCOPEEXIT, r->data, 
				r->last->line, r->last->col, NULL);

	if (r->tbl) {
		(*r->msg)(MANDOCERR_SCOPEEXIT, r->data, 
				r->tbl->line, r->tbl->pos, NULL);
		tbl_end(r->tbl);
		r->tbl = NULL;
	}
}


/*
 * Parse a roff node's type from the input buffer.  This must be in the
 * form of ".foo xxx" in the usual way.
 */
static enum rofft
roff_parse(struct roff *r, const char *buf, int *pos)
{
	const char	*mac;
	size_t		 maclen;
	enum rofft	 t;

	assert(ROFF_CTL(buf[*pos]));
	(*pos)++;

	while (' ' == buf[*pos] || '\t' == buf[*pos])
		(*pos)++;

	if ('\0' == buf[*pos])
		return(ROFF_MAX);

	mac = buf + *pos;
	maclen = strcspn(mac, " \\\t\0");

	t = (r->current_string = roff_getstrn(r, mac, maclen))
	    ? ROFF_USERDEF : roff_hash_find(mac, maclen);

	*pos += maclen;
	while (buf[*pos] && ' ' == buf[*pos])
		(*pos)++;

	return(t);
}


static int
roff_parse_nat(const char *buf, unsigned int *res)
{
	char		*ep;
	long		 lval;

	errno = 0;
	lval = strtol(buf, &ep, 10);
	if (buf[0] == '\0' || *ep != '\0')
		return(0);
	if ((errno == ERANGE && 
			(lval == LONG_MAX || lval == LONG_MIN)) ||
			(lval > INT_MAX || lval < 0))
		return(0);

	*res = (unsigned int)lval;
	return(1);
}


/* ARGSUSED */
static enum rofferr
roff_cblock(ROFF_ARGS)
{

	/*
	 * A block-close `..' should only be invoked as a child of an
	 * ignore macro, otherwise raise a warning and just ignore it.
	 */

	if (NULL == r->last) {
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	switch (r->last->tok) {
	case (ROFF_am):
		/* FALLTHROUGH */
	case (ROFF_ami):
		/* FALLTHROUGH */
	case (ROFF_am1):
		/* FALLTHROUGH */
	case (ROFF_de):
		/* ROFF_de1 is remapped to ROFF_de in roff_block(). */
		/* FALLTHROUGH */
	case (ROFF_dei):
		/* FALLTHROUGH */
	case (ROFF_ig):
		break;
	default:
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	if ((*bufp)[pos])
		(*r->msg)(MANDOCERR_ARGSLOST, r->data, ln, pos, NULL);

	roffnode_pop(r);
	roffnode_cleanscope(r);
	return(ROFF_IGN);

}


static void
roffnode_cleanscope(struct roff *r)
{

	while (r->last) {
		if (--r->last->endspan < 0)
			break;
		roffnode_pop(r);
	}
}


/* ARGSUSED */
static enum rofferr
roff_ccond(ROFF_ARGS)
{

	if (NULL == r->last) {
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	switch (r->last->tok) {
	case (ROFF_el):
		/* FALLTHROUGH */
	case (ROFF_ie):
		/* FALLTHROUGH */
	case (ROFF_if):
		break;
	default:
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	if (r->last->endspan > -1) {
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	if ((*bufp)[pos])
		(*r->msg)(MANDOCERR_ARGSLOST, r->data, ln, pos, NULL);

	roffnode_pop(r);
	roffnode_cleanscope(r);
	return(ROFF_IGN);
}


/* ARGSUSED */
static enum rofferr
roff_block(ROFF_ARGS)
{
	int		sv;
	size_t		sz;
	char		*name;

	name = NULL;

	if (ROFF_ig != tok) {
		if ('\0' == (*bufp)[pos]) {
			(*r->msg)(MANDOCERR_NOARGS, r->data, ln, ppos, NULL);
			return(ROFF_IGN);
		}

		/*
		 * Re-write `de1', since we don't really care about
		 * groff's strange compatibility mode, into `de'.
		 */

		if (ROFF_de1 == tok)
			tok = ROFF_de;
		if (ROFF_de == tok)
			name = *bufp + pos;
		else
			(*r->msg)(MANDOCERR_REQUEST, r->data, ln, ppos,
			    roffs[tok].name);

		while ((*bufp)[pos] && ' ' != (*bufp)[pos])
			pos++;

		while (' ' == (*bufp)[pos])
			(*bufp)[pos++] = '\0';
	}

	roffnode_push(r, tok, name, ln, ppos);

	/*
	 * At the beginning of a `de' macro, clear the existing string
	 * with the same name, if there is one.  New content will be
	 * added from roff_block_text() in multiline mode.
	 */

	if (ROFF_de == tok)
		roff_setstr(r, name, "", 0);

	if ('\0' == (*bufp)[pos])
		return(ROFF_IGN);

	/* If present, process the custom end-of-line marker. */

	sv = pos;
	while ((*bufp)[pos] &&
			' ' != (*bufp)[pos] && 
			'\t' != (*bufp)[pos])
		pos++;

	/*
	 * Note: groff does NOT like escape characters in the input.
	 * Instead of detecting this, we're just going to let it fly and
	 * to hell with it.
	 */

	assert(pos > sv);
	sz = (size_t)(pos - sv);

	if (1 == sz && '.' == (*bufp)[sv])
		return(ROFF_IGN);

	r->last->end = mandoc_malloc(sz + 1);

	memcpy(r->last->end, *bufp + sv, sz);
	r->last->end[(int)sz] = '\0';

	if ((*bufp)[pos])
		(*r->msg)(MANDOCERR_ARGSLOST, r->data, ln, pos, NULL);

	return(ROFF_IGN);
}


/* ARGSUSED */
static enum rofferr
roff_block_sub(ROFF_ARGS)
{
	enum rofft	t;
	int		i, j;

	/*
	 * First check whether a custom macro exists at this level.  If
	 * it does, then check against it.  This is some of groff's
	 * stranger behaviours.  If we encountered a custom end-scope
	 * tag and that tag also happens to be a "real" macro, then we
	 * need to try interpreting it again as a real macro.  If it's
	 * not, then return ignore.  Else continue.
	 */

	if (r->last->end) {
		i = pos + 1;
		while (' ' == (*bufp)[i] || '\t' == (*bufp)[i])
			i++;

		for (j = 0; r->last->end[j]; j++, i++)
			if ((*bufp)[i] != r->last->end[j])
				break;

		if ('\0' == r->last->end[j] && 
				('\0' == (*bufp)[i] ||
				 ' ' == (*bufp)[i] ||
				 '\t' == (*bufp)[i])) {
			roffnode_pop(r);
			roffnode_cleanscope(r);

			if (ROFF_MAX != roff_parse(r, *bufp, &pos))
				return(ROFF_RERUN);
			return(ROFF_IGN);
		}
	}

	/*
	 * If we have no custom end-query or lookup failed, then try
	 * pulling it out of the hashtable.
	 */

	ppos = pos;
	t = roff_parse(r, *bufp, &pos);

	/*
	 * Macros other than block-end are only significant
	 * in `de' blocks; elsewhere, simply throw them away.
	 */
	if (ROFF_cblock != t) {
		if (ROFF_de == tok)
			roff_setstr(r, r->last->name, *bufp + ppos, 1);
		return(ROFF_IGN);
	}

	assert(roffs[t].proc);
	return((*roffs[t].proc)(r, t, bufp, szp, 
				ln, ppos, pos, offs));
}


/* ARGSUSED */
static enum rofferr
roff_block_text(ROFF_ARGS)
{

	if (ROFF_de == tok)
		roff_setstr(r, r->last->name, *bufp + pos, 1);

	return(ROFF_IGN);
}


/* ARGSUSED */
static enum rofferr
roff_cond_sub(ROFF_ARGS)
{
	enum rofft	 t;
	enum roffrule	 rr;

	ppos = pos;
	rr = r->last->rule;

	/* 
	 * Clean out scope.  If we've closed ourselves, then don't
	 * continue. 
	 */

	roffnode_cleanscope(r);

	if (ROFF_MAX == (t = roff_parse(r, *bufp, &pos))) {
		if ('\\' == (*bufp)[pos] && '}' == (*bufp)[pos + 1])
			return(roff_ccond
				(r, ROFF_ccond, bufp, szp,
				 ln, pos, pos + 2, offs));
		return(ROFFRULE_DENY == rr ? ROFF_IGN : ROFF_CONT);
	}

	/*
	 * A denied conditional must evaluate its children if and only
	 * if they're either structurally required (such as loops and
	 * conditionals) or a closing macro.
	 */
	if (ROFFRULE_DENY == rr)
		if ( ! (ROFFMAC_STRUCT & roffs[t].flags))
			if (ROFF_ccond != t)
				return(ROFF_IGN);

	assert(roffs[t].proc);
	return((*roffs[t].proc)(r, t, bufp, szp, 
				ln, ppos, pos, offs));
}


/* ARGSUSED */
static enum rofferr
roff_cond_text(ROFF_ARGS)
{
	char		*ep, *st;
	enum roffrule	 rr;

	rr = r->last->rule;

	/*
	 * We display the value of the text if out current evaluation
	 * scope permits us to do so.
	 */

	/* FIXME: use roff_ccond? */

	st = &(*bufp)[pos];
	if (NULL == (ep = strstr(st, "\\}"))) {
		roffnode_cleanscope(r);
		return(ROFFRULE_DENY == rr ? ROFF_IGN : ROFF_CONT);
	}

	if (ep == st || (ep > st && '\\' != *(ep - 1)))
		roffnode_pop(r);

	roffnode_cleanscope(r);
	return(ROFFRULE_DENY == rr ? ROFF_IGN : ROFF_CONT);
}


static enum roffrule
roff_evalcond(const char *v, int *pos)
{

	switch (v[*pos]) {
	case ('n'):
		(*pos)++;
		return(ROFFRULE_ALLOW);
	case ('e'):
		/* FALLTHROUGH */
	case ('o'):
		/* FALLTHROUGH */
	case ('t'):
		(*pos)++;
		return(ROFFRULE_DENY);
	default:
		break;
	}

	while (v[*pos] && ' ' != v[*pos])
		(*pos)++;
	return(ROFFRULE_DENY);
}

/* ARGSUSED */
static enum rofferr
roff_line_ignore(ROFF_ARGS)
{

	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_line_error(ROFF_ARGS)
{

	(*r->msg)(MANDOCERR_REQUEST, r->data, ln, ppos, roffs[tok].name);
	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_cond(ROFF_ARGS)
{
	int		 sv;
	enum roffrule	 rule;

	/* Stack overflow! */

	if (ROFF_ie == tok && r->rstackpos == RSTACK_MAX - 1) {
		(*r->msg)(MANDOCERR_MEM, r->data, ln, ppos, NULL);
		return(ROFF_ERR);
	}

	/* First, evaluate the conditional. */

	if (ROFF_el == tok) {
		/* 
		 * An `.el' will get the value of the current rstack
		 * entry set in prior `ie' calls or defaults to DENY.
	 	 */
		if (r->rstackpos < 0)
			rule = ROFFRULE_DENY;
		else
			rule = r->rstack[r->rstackpos];
	} else
		rule = roff_evalcond(*bufp, &pos);

	sv = pos;

	while (' ' == (*bufp)[pos])
		pos++;

	/*
	 * Roff is weird.  If we have just white-space after the
	 * conditional, it's considered the BODY and we exit without
	 * really doing anything.  Warn about this.  It's probably
	 * wrong.
	 */

	if ('\0' == (*bufp)[pos] && sv != pos) {
		(*r->msg)(MANDOCERR_NOARGS, r->data, ln, ppos, NULL);
		return(ROFF_IGN);
	}

	roffnode_push(r, tok, NULL, ln, ppos);

	r->last->rule = rule;

	if (ROFF_ie == tok) {
		/*
		 * An if-else will put the NEGATION of the current
		 * evaluated conditional into the stack.
		 */
		r->rstackpos++;
		if (ROFFRULE_DENY == r->last->rule)
			r->rstack[r->rstackpos] = ROFFRULE_ALLOW;
		else
			r->rstack[r->rstackpos] = ROFFRULE_DENY;
	}

	/* If the parent has false as its rule, then so do we. */

	if (r->last->parent && ROFFRULE_DENY == r->last->parent->rule)
		r->last->rule = ROFFRULE_DENY;

	/*
	 * Determine scope.  If we're invoked with "\{" trailing the
	 * conditional, then we're in a multiline scope.  Else our scope
	 * expires on the next line.
	 */

	r->last->endspan = 1;

	if ('\\' == (*bufp)[pos] && '{' == (*bufp)[pos + 1]) {
		r->last->endspan = -1;
		pos += 2;
	} 

	/*
	 * If there are no arguments on the line, the next-line scope is
	 * assumed.
	 */

	if ('\0' == (*bufp)[pos])
		return(ROFF_IGN);

	/* Otherwise re-run the roff parser after recalculating. */

	*offs = pos;
	return(ROFF_RERUN);
}


/* ARGSUSED */
static enum rofferr
roff_ds(ROFF_ARGS)
{
	char		*name, *string;

	/*
	 * A symbol is named by the first word following the macro
	 * invocation up to a space.  Its value is anything after the
	 * name's trailing whitespace and optional double-quote.  Thus,
	 *
	 *  [.ds foo "bar  "     ]
	 *
	 * will have `bar  "     ' as its value.
	 */

	name = *bufp + pos;
	if ('\0' == *name)
		return(ROFF_IGN);

	string = name;
	/* Read until end of name. */
	while (*string && ' ' != *string)
		string++;

	/* Nil-terminate name. */
	if (*string)
		*(string++) = '\0';
	
	/* Read past spaces. */
	while (*string && ' ' == *string)
		string++;

	/* Read passed initial double-quote. */
	if (*string && '"' == *string)
		string++;

	/* The rest is the value. */
	roff_setstr(r, name, string, 0);
	return(ROFF_IGN);
}


/* ARGSUSED */
static enum rofferr
roff_nr(ROFF_ARGS)
{
	const char	*key, *val;
	struct reg	*rg;

	key = &(*bufp)[pos];
	rg = r->regs->regs;

	/* Parse register request. */
	while ((*bufp)[pos] && ' ' != (*bufp)[pos])
		pos++;

	/*
	 * Set our nil terminator.  Because this line is going to be
	 * ignored anyway, we can munge it as we please.
	 */
	if ((*bufp)[pos])
		(*bufp)[pos++] = '\0';

	/* Skip whitespace to register token. */
	while ((*bufp)[pos] && ' ' == (*bufp)[pos])
		pos++;

	val = &(*bufp)[pos];

	/* Process register token. */

	if (0 == strcmp(key, "nS")) {
		rg[(int)REG_nS].set = 1;
		if ( ! roff_parse_nat(val, &rg[(int)REG_nS].v.u))
			rg[(int)REG_nS].v.u = 0;
	}

	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_TE(ROFF_ARGS)
{

	if (NULL == r->tbl)
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
	else
		tbl_end(r->tbl);

	r->tbl = NULL;
	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_T_(ROFF_ARGS)
{

	if (NULL == r->tbl)
		(*r->msg)(MANDOCERR_NOSCOPE, r->data, ln, ppos, NULL);
	else
		tbl_restart(ppos, ln, r->tbl);

	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_TS(ROFF_ARGS)
{
	struct tbl_node	*t;

	if (r->tbl) {
		(*r->msg)(MANDOCERR_SCOPEBROKEN, r->data, ln, ppos, NULL);
		tbl_end(r->tbl);
	}

	t = tbl_alloc(ppos, ln, r->data, r->msg);

	if (r->last_tbl)
		r->last_tbl->next = t;
	else
		r->first_tbl = r->last_tbl = t;

	r->tbl = r->last_tbl = t;
	return(ROFF_IGN);
}

/* ARGSUSED */
static enum rofferr
roff_so(ROFF_ARGS)
{
	char *name;

	(*r->msg)(MANDOCERR_SO, r->data, ln, ppos, NULL);

	/*
	 * Handle `so'.  Be EXTREMELY careful, as we shouldn't be
	 * opening anything that's not in our cwd or anything beneath
	 * it.  Thus, explicitly disallow traversing up the file-system
	 * or using absolute paths.
	 */

	name = *bufp + pos;
	if ('/' == *name || strstr(name, "../") || strstr(name, "/..")) {
		(*r->msg)(MANDOCERR_SOPATH, r->data, ln, pos, NULL);
		return(ROFF_ERR);
	}

	*offs = pos;
	return(ROFF_SO);
}

/* ARGSUSED */
static enum rofferr
roff_userdef(ROFF_ARGS)
{
	const char	 *arg[9];
	char		 *cp, *n1, *n2;
	int		  i;

	/*
	 * Collect pointers to macro argument strings
	 * and null-terminate them.
	 */
	cp = *bufp + pos;
	for (i = 0; i < 9; i++)
		arg[i] = '\0' == *cp ? "" :
		    mandoc_getarg(&cp, r->msg, r->data, ln, &pos);

	/*
	 * Expand macro arguments.
	 */
	*szp = 0;
	n1 = cp = mandoc_strdup(r->current_string);
	while (NULL != (cp = strstr(cp, "\\$"))) {
		i = cp[2] - '1';
		if (0 > i || 8 < i) {
			/* Not an argument invocation. */
			cp += 2;
			continue;
		}

		*szp = strlen(n1) - 3 + strlen(arg[i]) + 1;
		n2 = mandoc_malloc(*szp);

		strlcpy(n2, n1, (size_t)(cp - n1 + 1));
		strlcat(n2, arg[i], *szp);
		strlcat(n2, cp + 3, *szp);

		cp = n2 + (cp - n1);
		free(n1);
		n1 = n2;
	}

	/*
	 * Replace the macro invocation
	 * by the expanded macro.
	 */
	free(*bufp);
	*bufp = n1;
	if (0 == *szp)
		*szp = strlen(*bufp) + 1;

	return(*szp > 1 && '\n' == (*bufp)[(int)*szp - 2] ?
	   ROFF_REPARSE : ROFF_APPEND);
}

/*
 * Store *string into the user-defined string called *name.
 * In multiline mode, append to an existing entry and append '\n';
 * else replace the existing entry, if there is one.
 * To clear an existing entry, call with (*r, *name, NULL, 0).
 */
static void
roff_setstr(struct roff *r, const char *name, const char *string,
	int multiline)
{
	struct roffstr	 *n;
	char		 *c;
	size_t		  oldch, newch;

	/* Search for an existing string with the same name. */
	n = r->first_string;
	while (n && strcmp(name, n->name))
		n = n->next;

	if (NULL == n) {
		/* Create a new string table entry. */
		n = mandoc_malloc(sizeof(struct roffstr));
		n->name = mandoc_strdup(name);
		n->string = NULL;
		n->next = r->first_string;
		r->first_string = n;
	} else if (0 == multiline) {
		/* In multiline mode, append; else replace. */
		free(n->string);
		n->string = NULL;
	}

	if (NULL == string)
		return;

	/*
	 * One additional byte for the '\n' in multiline mode,
	 * and one for the terminating '\0'.
	 */
	newch = strlen(string) + (multiline ? 2 : 1);
	if (NULL == n->string) {
		n->string = mandoc_malloc(newch);
		*n->string = '\0';
		oldch = 0;
	} else {
		oldch = strlen(n->string);
		n->string = mandoc_realloc(n->string, oldch + newch);
	}

	/* Skip existing content in the destination buffer. */
	c = n->string + oldch;

	/* Append new content to the destination buffer. */
	while (*string) {
		/*
		 * Rudimentary roff copy mode:
		 * Handle escaped backslashes.
		 */
		if ('\\' == *string && '\\' == *(string + 1))
			string++;
		*c++ = *string++;
	}

	/* Append terminating bytes. */
	if (multiline)
		*c++ = '\n';
	*c = '\0';
}


static const char *
roff_getstrn(const struct roff *r, const char *name, size_t len)
{
	const struct roffstr *n;

	n = r->first_string;
	while (n && (strncmp(name, n->name, len) || '\0' != n->name[(int)len]))
		n = n->next;

	return(n ? n->string : NULL);
}


static void
roff_freestr(struct roff *r)
{
	struct roffstr	 *n, *nn;

	for (n = r->first_string; n; n = nn) {
		free(n->name);
		free(n->string);
		nn = n->next;
		free(n);
	}

	r->first_string = NULL;
}

const struct tbl_span *
roff_span(const struct roff *r)
{
	
	return(r->tbl ? tbl_span(r->tbl) : NULL);
}
