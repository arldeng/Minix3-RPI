/*	$Vendor-Id: man.h,v 1.50 2011/01/01 12:59:17 kristaps Exp $ */
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
#ifndef MAN_H
#define MAN_H

/* 
 * What follows is a list of ALL possible macros. 
 */
enum	mant {
	MAN_br = 0,
	MAN_TH,
	MAN_SH,
	MAN_SS,
	MAN_TP,
	MAN_LP,
	MAN_PP,
	MAN_P,
	MAN_IP,
	MAN_HP,
	MAN_SM,
	MAN_SB,
	MAN_BI,
	MAN_IB,
	MAN_BR,
	MAN_RB,
	MAN_R,
	MAN_B,
	MAN_I,
	MAN_IR,
	MAN_RI,
	MAN_na,
	MAN_sp,
	MAN_nf,
	MAN_fi,
	MAN_RE,
	MAN_RS,
	MAN_DT,
	MAN_UC,
	MAN_PD,
	MAN_AT,
	MAN_in,
	MAN_ft,
	MAN_MAX
};

/* 
 * Type of a syntax node. 
 */
enum	man_type {
	MAN_TEXT,
	MAN_ELEM,
	MAN_ROOT,
	MAN_BLOCK,
	MAN_HEAD,
	MAN_BODY,
	MAN_TBL
};

/* 
 * Information from prologue. 
 */
struct	man_meta {
	char		*msec; /* `TH' section (1, 3p, etc.) */
	time_t		 date; /* `TH' normalised date */
	char		*rawdate; /* raw `TH' date */
	char		*vol; /* `TH' volume */
	char		*title; /* `TH' title (e.g., FOO) */
	char		*source; /* `TH' source (e.g., GNU) */
};

/* 
 * Single node in tree-linked AST. 
 */
struct	man_node {
	struct man_node	*parent; /* parent AST node */
	struct man_node	*child; /* first child AST node */
	struct man_node	*next; /* sibling AST node */
	struct man_node	*prev; /* prior sibling AST node */
	int		 nchild; /* number children */
	int		 line;
	int		 pos;
	enum mant	 tok; /* tok or MAN__MAX if none */
	int		 flags;
#define	MAN_VALID	(1 << 0) /* has been validated */
#define	MAN_EOS		(1 << 2) /* at sentence boundary */
	enum man_type	 type; /* AST node type */
	char		*string; /* TEXT node argument */
	struct man_node	*head; /* BLOCK node HEAD ptr */
	struct man_node	*body; /* BLOCK node BODY ptr */
	const struct tbl_span *span; /* TBL */
};

/*
 * Names of macros.  Index is enum mant.  Indexing into this returns
 * the normalised name, e.g., man_macronames[MAN_SH] -> "SH".
 */
extern	const char *const *man_macronames;

__BEGIN_DECLS

struct	man;

void	 	  man_free(struct man *);
struct	man	 *man_alloc(struct regset *, void *, mandocmsg);
void		  man_reset(struct man *);
int	 	  man_parseln(struct man *, int, char *, int);
int		  man_endparse(struct man *);
int		  man_addspan(struct man *,
			const struct tbl_span *);

const struct man_node *man_node(const struct man *);
const struct man_meta *man_meta(const struct man *);

__END_DECLS

#endif /*!MAN_H*/
