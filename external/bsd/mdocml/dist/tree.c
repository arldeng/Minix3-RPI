/*	$Vendor-Id: tree.c,v 1.31 2011/01/03 13:59:21 kristaps Exp $ */
/*
 * Copyright (c) 2008, 2009 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "mandoc.h"
#include "mdoc.h"
#include "man.h"
#include "main.h"

static	void	print_mdoc(const struct mdoc_node *, int);
static	void	print_man(const struct man_node *, int);
static	void	print_span(const struct tbl_span *, int);


/* ARGSUSED */
void
tree_mdoc(void *arg, const struct mdoc *mdoc)
{

	print_mdoc(mdoc_node(mdoc), 0);
}


/* ARGSUSED */
void
tree_man(void *arg, const struct man *man)
{

	print_man(man_node(man), 0);
}


static void
print_mdoc(const struct mdoc_node *n, int indent)
{
	const char	 *p, *t;
	int		  i, j;
	size_t		  argc, sz;
	char		**params;
	struct mdoc_argv *argv;

	argv = NULL;
	argc = sz = 0;
	params = NULL;

	switch (n->type) {
	case (MDOC_ROOT):
		t = "root";
		break;
	case (MDOC_BLOCK):
		t = "block";
		break;
	case (MDOC_HEAD):
		t = "block-head";
		break;
	case (MDOC_BODY):
		if (n->end)
			t = "body-end";
		else
			t = "block-body";
		break;
	case (MDOC_TAIL):
		t = "block-tail";
		break;
	case (MDOC_ELEM):
		t = "elem";
		break;
	case (MDOC_TEXT):
		t = "text";
		break;
	case (MDOC_TBL):
		t = "tbl";
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	p = NULL;

	switch (n->type) {
	case (MDOC_TEXT):
		p = n->string;
		break;
	case (MDOC_BODY):
		p = mdoc_macronames[n->tok];
		break;
	case (MDOC_HEAD):
		p = mdoc_macronames[n->tok];
		break;
	case (MDOC_TAIL):
		p = mdoc_macronames[n->tok];
		break;
	case (MDOC_ELEM):
		p = mdoc_macronames[n->tok];
		if (n->args) {
			argv = n->args->argv;
			argc = n->args->argc;
		}
		break;
	case (MDOC_BLOCK):
		p = mdoc_macronames[n->tok];
		if (n->args) {
			argv = n->args->argv;
			argc = n->args->argc;
		}
		break;
	case (MDOC_TBL):
		break;
	case (MDOC_ROOT):
		p = "root";
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	if (n->span) {
		assert(NULL == p);
		print_span(n->span, indent);
	} else {
		for (i = 0; i < indent; i++)
			putchar('\t');

		printf("%s (%s)", p, t);

		for (i = 0; i < (int)argc; i++) {
			printf(" -%s", mdoc_argnames[argv[i].arg]);
			if (argv[i].sz > 0)
				printf(" [");
			for (j = 0; j < (int)argv[i].sz; j++)
				printf(" [%s]", argv[i].value[j]);
			if (argv[i].sz > 0)
				printf(" ]");
		}
		
		for (i = 0; i < (int)sz; i++)
			printf(" [%s]", params[i]);

		printf(" %d:%d", n->line, n->pos);
	}

	putchar('\n');

	if (n->child)
		print_mdoc(n->child, indent + 1);
	if (n->next)
		print_mdoc(n->next, indent);
}


static void
print_man(const struct man_node *n, int indent)
{
	const char	 *p, *t;
	int		  i;

	switch (n->type) {
	case (MAN_ROOT):
		t = "root";
		break;
	case (MAN_ELEM):
		t = "elem";
		break;
	case (MAN_TEXT):
		t = "text";
		break;
	case (MAN_BLOCK):
		t = "block";
		break;
	case (MAN_HEAD):
		t = "block-head";
		break;
	case (MAN_BODY):
		t = "block-body";
		break;
	case (MAN_TBL):
		t = "tbl";
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	p = NULL;

	switch (n->type) {
	case (MAN_TEXT):
		p = n->string;
		break;
	case (MAN_ELEM):
		/* FALLTHROUGH */
	case (MAN_BLOCK):
		/* FALLTHROUGH */
	case (MAN_HEAD):
		/* FALLTHROUGH */
	case (MAN_BODY):
		p = man_macronames[n->tok];
		break;
	case (MAN_ROOT):
		p = "root";
		break;
	case (MAN_TBL):
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	if (n->span) {
		assert(NULL == p);
		print_span(n->span, indent);
	} else {
		for (i = 0; i < indent; i++)
			putchar('\t');
		printf("%s (%s) %d:%d", p, t, n->line, n->pos);
	}

	putchar('\n');

	if (n->child)
		print_man(n->child, indent + 1);
	if (n->next)
		print_man(n->next, indent);
}

static void
print_span(const struct tbl_span *sp, int indent)
{
	const struct tbl_dat *dp;
	int		 i;

	for (i = 0; i < indent; i++)
		putchar('\t');

	printf("tbl: ");

	switch (sp->pos) {
	case (TBL_SPAN_HORIZ):
		putchar('-');
		return;
	case (TBL_SPAN_DHORIZ):
		putchar('=');
		return;
	default:
		break;
	}

	for (dp = sp->first; dp; dp = dp->next) {
		switch (dp->pos) {
		case (TBL_DATA_HORIZ):
			/* FALLTHROUGH */
		case (TBL_DATA_NHORIZ):
			putchar('-');
			continue;
		case (TBL_DATA_DHORIZ):
			/* FALLTHROUGH */
		case (TBL_DATA_NDHORIZ):
			putchar('=');
			continue;
		default:
			break;
		}
		printf("[%s%s]", dp->string, dp->layout ?  "" : "*");
		if (dp->next)
			putchar(' ');
	}
}
