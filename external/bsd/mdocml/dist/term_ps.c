/*	$Vendor-Id: term_ps.c,v 1.45 2010/09/27 23:03:44 schwarze Exp $ */
/*
 * Copyright (c) 2010 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "mandoc.h"
#include "out.h"
#include "main.h"
#include "term.h"

/* Convert PostScript point "x" to an AFM unit. */
#define	PNT2AFM(p, x) /* LINTED */ \
	(size_t)((double)(x) * (1000.0 / (double)(p)->engine.ps.scale))

/* Convert an AFM unit "x" to a PostScript points */
#define	AFM2PNT(p, x) /* LINTED */ \
	((double)(x) / (1000.0 / (double)(p)->engine.ps.scale))

struct	glyph {
	unsigned short	  wx; /* WX in AFM */
};

struct	font {
	const char	 *name; /* FontName in AFM */
#define	MAXCHAR		  95 /* total characters we can handle */
	struct glyph	  gly[MAXCHAR]; /* glyph metrics */
};

/*
 * We define, for the time being, three fonts: bold, oblique/italic, and
 * normal (roman).  The following table hard-codes the font metrics for
 * ASCII, i.e., 32--127.
 */

static	const struct font fonts[TERMFONT__MAX] = {
	{ "Times-Roman", {
		{ 250 },
		{ 333 },
		{ 408 },
		{ 500 },
		{ 500 },
		{ 833 },
		{ 778 },
		{ 333 },
		{ 333 },
		{ 333 },
		{ 500 },
		{ 564 },
		{ 250 },
		{ 333 },
		{ 250 },
		{ 278 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 500 },
		{ 278 },
		{ 278 },
		{ 564 },
		{ 564 },
		{ 564 },
		{ 444 },
		{ 921 },
		{ 722 },
		{ 667 },
		{ 667 },
		{ 722 },
		{ 611 },
		{ 556 },
		{ 722 },
		{ 722 },
		{ 333 },
		{ 389 },
		{ 722 },
		{ 611 },
		{ 889 },
		{ 722 },
		{ 722 },
		{ 556 },
		{ 722 },
		{ 667 },
		{ 556 },
		{ 611 },
		{ 722 },
		{ 722 },
		{ 944 },
		{ 722 },
		{ 722 },
		{ 611 },
		{ 333 },
		{ 278 },
		{ 333 },
		{ 469 },
		{ 500 },
		{ 333 },
		{ 444 },
		{ 500 },
		{ 444 },
		{  500},
		{  444},
		{  333},
		{  500},
		{  500},
		{  278},
		{  278},
		{  500},
		{  278},
		{  778},
		{  500},
		{  500},
		{  500},
		{  500},
		{  333},
		{  389},
		{  278},
		{  500},
		{  500},
		{  722},
		{  500},
		{  500},
		{  444},
		{  480},
		{  200},
		{  480},
		{  541},
	} },
	{ "Times-Bold", {
		{ 250  },
		{ 333  },
		{ 555  },
		{ 500  },
		{ 500  },
		{ 1000 },
		{ 833  },
		{ 333  },
		{ 333  },
		{ 333  },
		{ 500  },
		{ 570  },
		{ 250  },
		{ 333  },
		{ 250  },
		{ 278  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 333  },
		{ 333  },
		{ 570  },
		{ 570  },
		{ 570  },
		{ 500  },
		{ 930  },
		{ 722  },
		{ 667  },
		{ 722  },
		{ 722  },
		{ 667  },
		{ 611  },
		{ 778  },
		{ 778  },
		{ 389  },
		{ 500  },
		{ 778  },
		{ 667  },
		{ 944  },
		{ 722  },
		{ 778  },
		{ 611  },
		{ 778  },
		{ 722  },
		{ 556  },
		{ 667  },
		{ 722  },
		{ 722  },
		{ 1000 },
		{ 722  },
		{ 722  },
		{ 667  },
		{ 333  },
		{ 278  },
		{ 333  },
		{ 581  },
		{ 500  },
		{ 333  },
		{ 500  },
		{ 556  },
		{ 444  },
		{  556 },
		{  444 },
		{  333 },
		{  500 },
		{  556 },
		{  278 },
		{  333 },
		{  556 },
		{  278 },
		{  833 },
		{  556 },
		{  500 },
		{  556 },
		{  556 },
		{  444 },
		{  389 },
		{  333 },
		{  556 },
		{  500 },
		{  722 },
		{  500 },
		{  500 },
		{  444 },
		{  394 },
		{  220 },
		{  394 },
		{  520 },
	} },
	{ "Times-Italic", {
		{ 250  },
		{ 333  },
		{ 420  },
		{ 500  },
		{ 500  },
		{ 833  },
		{ 778  },
		{ 333  },
		{ 333  },
		{ 333  },
		{ 500  },
		{ 675  },
		{ 250  },
		{ 333  },
		{ 250  },
		{ 278  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 500  },
		{ 333  },
		{ 333  },
		{ 675  },
		{ 675  },
		{ 675  },
		{ 500  },
		{ 920  },
		{ 611  },
		{ 611  },
		{ 667  },
		{ 722  },
		{ 611  },
		{ 611  },
		{ 722  },
		{ 722  },
		{ 333  },
		{ 444  },
		{ 667  },
		{ 556  },
		{ 833  },
		{ 667  },
		{ 722  },
		{ 611  },
		{ 722  },
		{ 611  },
		{ 500  },
		{ 556  },
		{ 722  },
		{ 611  },
		{ 833  },
		{ 611  },
		{ 556  },
		{ 556  },
		{ 389  },
		{ 278  },
		{ 389  },
		{ 422  },
		{ 500  },
		{ 333  },
		{ 500  },
		{ 500  },
		{ 444  },
		{  500 },
		{  444 },
		{  278 },
		{  500 },
		{  500 },
		{  278 },
		{  278 },
		{  444 },
		{  278 },
		{  722 },
		{  500 },
		{  500 },
		{  500 },
		{  500 },
		{  389 },
		{  389 },
		{  278 },
		{  500 },
		{  444 },
		{  667 },
		{  444 },
		{  444 },
		{  389 },
		{  400 },
		{  275 },
		{  400 },
		{  541 },
	} },
};

/* These work the buffer used by the header and footer. */
#define	PS_BUFSLOP	  128

static void
ps_growbuf(struct termp *p, size_t sz)
{
	if (p->engine.ps.psmargcur + sz <= p->engine.ps.psmargsz)
		return;

	if (sz < PS_BUFSLOP)
		sz = PS_BUFSLOP;

	p->engine.ps.psmargsz += sz;

	p->engine.ps.psmarg = realloc
		(p->engine.ps.psmarg,
		 p->engine.ps.psmargsz);
	
	if (NULL == p->engine.ps.psmarg) {
		perror(NULL);
		exit((int)MANDOCLEVEL_SYSERR);
	}
}

static	double		  ps_hspan(const struct termp *,
				const struct roffsu *);
static	size_t		  ps_width(const struct termp *, char);
static	void		  ps_advance(struct termp *, size_t);
static	void		  ps_begin(struct termp *);
static	void		  ps_closepage(struct termp *);
static	void		  ps_end(struct termp *);
static	void		  ps_endline(struct termp *);
static	void		  ps_fclose(struct termp *);
static	void		  ps_letter(struct termp *, char);
static	void		  ps_pclose(struct termp *);
static	void		  ps_pletter(struct termp *, int);
static	void		  ps_printf(struct termp *, const char *, ...);
static	void		  ps_putchar(struct termp *, char);
static	void		  ps_setfont(struct termp *, enum termfont);
static	struct termp	 *pspdf_alloc(char *);
static	void		  pdf_obj(struct termp *, size_t);


void *
pdf_alloc(char *outopts)
{
	struct termp	*p;

	if (NULL != (p = pspdf_alloc(outopts)))
		p->type = TERMTYPE_PDF;

	return(p);
}


void *
ps_alloc(char *outopts)
{
	struct termp	*p;

	if (NULL != (p = pspdf_alloc(outopts)))
		p->type = TERMTYPE_PS;

	return(p);
}


static struct termp *
pspdf_alloc(char *outopts)
{
	struct termp	*p;
	size_t		 pagex, pagey, marginx, marginy, lineheight;
	const char	*toks[2];
	const char	*pp;
	char		*v;

	if (NULL == (p = term_alloc(TERMENC_ASCII)))
		return(NULL);

	p->advance = ps_advance;
	p->begin = ps_begin;
	p->end = ps_end;
	p->endline = ps_endline;
	p->hspan = ps_hspan;
	p->letter = ps_letter;
	p->width = ps_width;
	
	toks[0] = "paper";
	toks[1] = NULL;

	pp = NULL;

	while (outopts && *outopts)
		switch (getsubopt(&outopts, UNCONST(toks), &v)) {
		case (0):
			pp = v;
			break;
		default:
			break;
		}

	/* Default to US letter (millimetres). */

	pagex = 216;
	pagey = 279;

	/*
	 * The ISO-269 paper sizes can be calculated automatically, but
	 * it would require bringing in -lm for pow() and I'd rather not
	 * do that.  So just do it the easy way for now.  Since this
	 * only happens once, I'm not terribly concerned.
	 */

	if (pp && strcasecmp(pp, "letter")) {
		if (0 == strcasecmp(pp, "a3")) {
			pagex = 297;
			pagey = 420;
		} else if (0 == strcasecmp(pp, "a4")) {
			pagex = 210;
			pagey = 297;
		} else if (0 == strcasecmp(pp, "a5")) {
			pagex = 148;
			pagey = 210;
		} else if (0 == strcasecmp(pp, "legal")) {
			pagex = 216;
			pagey = 356;
		} else if (2 != sscanf(pp, "%zux%zu", &pagex, &pagey))
			fprintf(stderr, "%s: Unknown paper\n", pp);
	} else if (NULL == pp)
		pp = "letter";

	/* 
	 * This MUST be defined before any PNT2AFM or AFM2PNT
	 * calculations occur.
	 */

	p->engine.ps.scale = 11;

	/* Remember millimetres -> AFM units. */

	pagex = PNT2AFM(p, ((double)pagex * 2.834));
	pagey = PNT2AFM(p, ((double)pagey * 2.834));

	/* Margins are 1/9 the page x and y. */

	marginx = /* LINTED */
		(size_t)((double)pagex / 9.0);
	marginy = /* LINTED */
		(size_t)((double)pagey / 9.0);

	/* Line-height is 1.4em. */

	lineheight = PNT2AFM(p, ((double)p->engine.ps.scale * 1.4));

	p->engine.ps.width = pagex;
	p->engine.ps.height = pagey;
	p->engine.ps.header = pagey - (marginy / 2) - (lineheight / 2);
	p->engine.ps.top = pagey - marginy;
	p->engine.ps.footer = (marginy / 2) - (lineheight / 2);
	p->engine.ps.bottom = marginy;
	p->engine.ps.left = marginx;
	p->engine.ps.lineheight = lineheight;

	p->defrmargin = pagex - (marginx * 2);
	return(p);
}


void
pspdf_free(void *arg)
{
	struct termp	*p;

	p = (struct termp *)arg;

	if (p->engine.ps.psmarg)
		free(p->engine.ps.psmarg);
	if (p->engine.ps.pdfobjs)
		free(p->engine.ps.pdfobjs);

	term_free(p);
}


static void
ps_printf(struct termp *p, const char *fmt, ...)
{
	va_list		 ap;
	int		 pos, len;

	va_start(ap, fmt);

	/*
	 * If we're running in regular mode, then pipe directly into
	 * vprintf().  If we're processing margins, then push the data
	 * into our growable margin buffer.
	 */

	if ( ! (PS_MARGINS & p->engine.ps.flags)) {
		len = vprintf(fmt, ap);
		va_end(ap);
		p->engine.ps.pdfbytes += /* LINTED */
			len < 0 ? 0 : (size_t)len;
		return;
	}

	/* 
	 * XXX: I assume that the in-margin print won't exceed
	 * PS_BUFSLOP (128 bytes), which is reasonable but still an
	 * assumption that will cause pukeage if it's not the case.
	 */

	ps_growbuf(p, PS_BUFSLOP);

	pos = (int)p->engine.ps.psmargcur;
	len = vsnprintf(&p->engine.ps.psmarg[pos], PS_BUFSLOP, fmt, ap);

	va_end(ap);

	p->engine.ps.psmargcur = strlen(p->engine.ps.psmarg);
}


static void
ps_putchar(struct termp *p, char c)
{
	int		 pos;

	/* See ps_printf(). */

	if ( ! (PS_MARGINS & p->engine.ps.flags)) {
		/* LINTED */
		putchar(c);
		p->engine.ps.pdfbytes++;
		return;
	}

	ps_growbuf(p, 2);

	pos = (int)p->engine.ps.psmargcur++;
	p->engine.ps.psmarg[pos++] = c;
	p->engine.ps.psmarg[pos] = '\0';
}


static void
pdf_obj(struct termp *p, size_t obj)
{

	assert(obj > 0);

	if ((obj - 1) >= p->engine.ps.pdfobjsz) {
		p->engine.ps.pdfobjsz = obj + 128;
		p->engine.ps.pdfobjs = realloc
			(p->engine.ps.pdfobjs, 
			 p->engine.ps.pdfobjsz * sizeof(size_t));
		if (NULL == p->engine.ps.pdfobjs) {
			perror(NULL);
			exit((int)MANDOCLEVEL_SYSERR);
		}
	}

	p->engine.ps.pdfobjs[(int)obj - 1] = p->engine.ps.pdfbytes;
	ps_printf(p, "%zu 0 obj\n", obj);
}


static void
ps_closepage(struct termp *p)
{
	int		 i;
	size_t		 len, base;

	/*
	 * Close out a page that we've already flushed to output.  In
	 * PostScript, we simply note that the page must be showed.  In
	 * PDF, we must now create the Length, Resource, and Page node
	 * for the page contents.
	 */

	assert(p->engine.ps.psmarg && p->engine.ps.psmarg[0]);
	ps_printf(p, "%s", p->engine.ps.psmarg);

	if (TERMTYPE_PS != p->type) {
		ps_printf(p, "ET\n");

		len = p->engine.ps.pdfbytes - p->engine.ps.pdflastpg;
		base = p->engine.ps.pages * 4 + p->engine.ps.pdfbody;

		ps_printf(p, "endstream\nendobj\n");

		/* Length of content. */
		pdf_obj(p, base + 1);
		ps_printf(p, "%zu\nendobj\n", len);

		/* Resource for content. */
		pdf_obj(p, base + 2);
		ps_printf(p, "<<\n/ProcSet [/PDF /Text]\n");
		ps_printf(p, "/Font <<\n");
		for (i = 0; i < (int)TERMFONT__MAX; i++) 
			ps_printf(p, "/F%d %d 0 R\n", i, 3 + i);
		ps_printf(p, ">>\n>>\n");

		/* Page node. */
		pdf_obj(p, base + 3);
		ps_printf(p, "<<\n");
		ps_printf(p, "/Type /Page\n");
		ps_printf(p, "/Parent 2 0 R\n");
		ps_printf(p, "/Resources %zu 0 R\n", base + 2);
		ps_printf(p, "/Contents %zu 0 R\n", base);
		ps_printf(p, ">>\nendobj\n");
	} else
		ps_printf(p, "showpage\n");

	p->engine.ps.pages++;
	p->engine.ps.psrow = p->engine.ps.top;
	assert( ! (PS_NEWPAGE & p->engine.ps.flags));
	p->engine.ps.flags |= PS_NEWPAGE;
}


/* ARGSUSED */
static void
ps_end(struct termp *p)
{
	size_t		 i, xref, base;

	/*
	 * At the end of the file, do one last showpage.  This is the
	 * same behaviour as groff(1) and works for multiple pages as
	 * well as just one.
	 */

	if ( ! (PS_NEWPAGE & p->engine.ps.flags)) {
		assert(0 == p->engine.ps.flags);
		assert('\0' == p->engine.ps.last);
		ps_closepage(p);
	}

	if (TERMTYPE_PS == p->type) {
		ps_printf(p, "%%%%Trailer\n");
		ps_printf(p, "%%%%Pages: %zu\n", p->engine.ps.pages);
		ps_printf(p, "%%%%EOF\n");
		return;
	} 

	pdf_obj(p, 2);
	ps_printf(p, "<<\n/Type /Pages\n");
	ps_printf(p, "/MediaBox [0 0 %zu %zu]\n",
			(size_t)AFM2PNT(p, p->engine.ps.width),
			(size_t)AFM2PNT(p, p->engine.ps.height));

	ps_printf(p, "/Count %zu\n", p->engine.ps.pages);
	ps_printf(p, "/Kids [");

	for (i = 0; i < p->engine.ps.pages; i++)
		ps_printf(p, " %zu 0 R", i * 4 +
				p->engine.ps.pdfbody + 3);

	base = (p->engine.ps.pages - 1) * 4 + 
		p->engine.ps.pdfbody + 4;

	ps_printf(p, "]\n>>\nendobj\n");
	pdf_obj(p, base);
	ps_printf(p, "<<\n");
	ps_printf(p, "/Type /Catalog\n");
	ps_printf(p, "/Pages 2 0 R\n");
	ps_printf(p, ">>\n");
	xref = p->engine.ps.pdfbytes;
	ps_printf(p, "xref\n");
	ps_printf(p, "0 %zu\n", base + 1);
	ps_printf(p, "0000000000 65535 f \n");

	for (i = 0; i < base; i++)
		ps_printf(p, "%.10zu 00000 n \n", 
				p->engine.ps.pdfobjs[(int)i]);

	ps_printf(p, "trailer\n");
	ps_printf(p, "<<\n");
	ps_printf(p, "/Size %zu\n", base + 1);
	ps_printf(p, "/Root %zu 0 R\n", base);
	ps_printf(p, "/Info 1 0 R\n");
	ps_printf(p, ">>\n");
	ps_printf(p, "startxref\n");
	ps_printf(p, "%zu\n", xref);
	ps_printf(p, "%%%%EOF\n");
}


static void
ps_begin(struct termp *p)
{
	time_t		 t;
	int		 i;

	/* 
	 * Print margins into margin buffer.  Nothing gets output to the
	 * screen yet, so we don't need to initialise the primary state.
	 */

	if (p->engine.ps.psmarg) {
		assert(p->engine.ps.psmargsz);
		p->engine.ps.psmarg[0] = '\0';
	}

	/*p->engine.ps.pdfbytes = 0;*/
	p->engine.ps.psmargcur = 0;
	p->engine.ps.flags = PS_MARGINS;
	p->engine.ps.pscol = p->engine.ps.left;
	p->engine.ps.psrow = p->engine.ps.header;

	ps_setfont(p, TERMFONT_NONE);

	(*p->headf)(p, p->argf);
	(*p->endline)(p);

	p->engine.ps.pscol = p->engine.ps.left;
	p->engine.ps.psrow = p->engine.ps.footer;

	(*p->footf)(p, p->argf);
	(*p->endline)(p);

	p->engine.ps.flags &= ~PS_MARGINS;

	assert(0 == p->engine.ps.flags);
	assert(p->engine.ps.psmarg);
	assert('\0' != p->engine.ps.psmarg[0]);

	/* 
	 * Print header and initialise page state.  Following this,
	 * stuff gets printed to the screen, so make sure we're sane.
	 */

	t = time(NULL);

	if (TERMTYPE_PS == p->type) {
		ps_printf(p, "%%!PS-Adobe-3.0\n");
		ps_printf(p, "%%%%Creator: mandoc-%s\n", VERSION);
		ps_printf(p, "%%%%CreationDate: %s", ctime(&t));
		ps_printf(p, "%%%%DocumentData: Clean7Bit\n");
		ps_printf(p, "%%%%Orientation: Portrait\n");
		ps_printf(p, "%%%%Pages: (atend)\n");
		ps_printf(p, "%%%%PageOrder: Ascend\n");
		ps_printf(p, "%%%%DocumentMedia: "
				"Default %zu %zu 0 () ()\n",
				(size_t)AFM2PNT(p, p->engine.ps.width),
				(size_t)AFM2PNT(p, p->engine.ps.height));
		ps_printf(p, "%%%%DocumentNeededResources: font");

		for (i = 0; i < (int)TERMFONT__MAX; i++)
			ps_printf(p, " %s", fonts[i].name);

		ps_printf(p, "\n%%%%EndComments\n");
	} else {
		ps_printf(p, "%%PDF-1.1\n");
		pdf_obj(p, 1);
		ps_printf(p, "<<\n");
		ps_printf(p, "/Creator mandoc-%s\n", VERSION);
		ps_printf(p, ">>\n");
		ps_printf(p, "endobj\n");

		for (i = 0; i < (int)TERMFONT__MAX; i++) {
			pdf_obj(p, (size_t)i + 3);
			ps_printf(p, "<<\n");
			ps_printf(p, "/Type /Font\n");
			ps_printf(p, "/Subtype /Type1\n");
			ps_printf(p, "/Name /F%zu\n", i);
			ps_printf(p, "/BaseFont /%s\n", fonts[i].name);
			ps_printf(p, ">>\n");
		}
	}

	p->engine.ps.pdfbody = (size_t)TERMFONT__MAX + 3;
	p->engine.ps.pscol = p->engine.ps.left;
	p->engine.ps.psrow = p->engine.ps.top;
	p->engine.ps.flags |= PS_NEWPAGE;
	ps_setfont(p, TERMFONT_NONE);
}


static void
ps_pletter(struct termp *p, int c)
{
	int		 f;

	/*
	 * If we haven't opened a page context, then output that we're
	 * in a new page and make sure the font is correctly set.
	 */

	if (PS_NEWPAGE & p->engine.ps.flags) {
		if (TERMTYPE_PS == p->type) {
			ps_printf(p, "%%%%Page: %zu %zu\n", 
					p->engine.ps.pages + 1, 
					p->engine.ps.pages + 1);
			ps_printf(p, "/%s %zu selectfont\n", 
					fonts[(int)p->engine.ps.lastf].name, 
					p->engine.ps.scale);
		} else {
			pdf_obj(p, p->engine.ps.pdfbody + 
					p->engine.ps.pages * 4);
			ps_printf(p, "<<\n");
			ps_printf(p, "/Length %zu 0 R\n", 
					p->engine.ps.pdfbody + 1 +
					p->engine.ps.pages * 4);
			ps_printf(p, ">>\nstream\n");
		}
		p->engine.ps.pdflastpg = p->engine.ps.pdfbytes;
		p->engine.ps.flags &= ~PS_NEWPAGE;
	}
	
	/*
	 * If we're not in a PostScript "word" context, then open one
	 * now at the current cursor.
	 */

	if ( ! (PS_INLINE & p->engine.ps.flags)) {
		if (TERMTYPE_PS != p->type) {
			ps_printf(p, "BT\n/F%d %zu Tf\n", 
					(int)p->engine.ps.lastf,
					p->engine.ps.scale);
			ps_printf(p, "%.3f %.3f Td\n(",
					AFM2PNT(p, p->engine.ps.pscol),
					AFM2PNT(p, p->engine.ps.psrow));
		} else
			ps_printf(p, "%.3f %.3f moveto\n(", 
					AFM2PNT(p, p->engine.ps.pscol),
					AFM2PNT(p, p->engine.ps.psrow));
		p->engine.ps.flags |= PS_INLINE;
	}

	assert( ! (PS_NEWPAGE & p->engine.ps.flags));

	/*
	 * We need to escape these characters as per the PostScript
	 * specification.  We would also escape non-graphable characters
	 * (like tabs), but none of them would get to this point and
	 * it's superfluous to abort() on them.
	 */

	switch (c) {
	case ('('):
		/* FALLTHROUGH */
	case (')'):
		/* FALLTHROUGH */
	case ('\\'):
		ps_putchar(p, '\\');
		break;
	default:
		break;
	}

	/* Write the character and adjust where we are on the page. */

	f = (int)p->engine.ps.lastf;

	if (c <= 32 || (c - 32 >= MAXCHAR)) {
		ps_putchar(p, ' ');
		p->engine.ps.pscol += (size_t)fonts[f].gly[0].wx;
		return;
	} 

	ps_putchar(p, (char)c);
	c -= 32;
	p->engine.ps.pscol += (size_t)fonts[f].gly[c].wx;
}


static void
ps_pclose(struct termp *p)
{

	/* 
	 * Spit out that we're exiting a word context (this is a
	 * "partial close" because we don't check the last-char buffer
	 * or anything).
	 */

	if ( ! (PS_INLINE & p->engine.ps.flags))
		return;
	
	if (TERMTYPE_PS != p->type) {
		ps_printf(p, ") Tj\nET\n");
	} else
		ps_printf(p, ") show\n");

	p->engine.ps.flags &= ~PS_INLINE;
}


static void
ps_fclose(struct termp *p)
{

	/*
	 * Strong closure: if we have a last-char, spit it out after
	 * checking that we're in the right font mode.  This will of
	 * course open a new scope, if applicable.
	 *
	 * Following this, close out any scope that's open.
	 */

	if ('\0' != p->engine.ps.last) {
		if (p->engine.ps.lastf != TERMFONT_NONE) {
			ps_pclose(p);
			ps_setfont(p, TERMFONT_NONE);
		}
		ps_pletter(p, p->engine.ps.last);
		p->engine.ps.last = '\0';
	}

	if ( ! (PS_INLINE & p->engine.ps.flags))
		return;

	ps_pclose(p);
}


static void
ps_letter(struct termp *p, char c)
{
	char		cc;

	/*
	 * State machine dictates whether to buffer the last character
	 * or not.  Basically, encoded words are detected by checking if
	 * we're an "8" and switching on the buffer.  Then we put "8" in
	 * our buffer, and on the next charater, flush both character
	 * and buffer.  Thus, "regular" words are detected by having a
	 * regular character and a regular buffer character.
	 */

	if ('\0' == p->engine.ps.last) {
		assert(8 != c);
		p->engine.ps.last = c;
		return;
	} else if (8 == p->engine.ps.last) {
		assert(8 != c);
		p->engine.ps.last = '\0';
	} else if (8 == c) {
		assert(8 != p->engine.ps.last);
		if ('_' == p->engine.ps.last) {
			if (p->engine.ps.lastf != TERMFONT_UNDER) {
				ps_pclose(p);
				ps_setfont(p, TERMFONT_UNDER);
			}
		} else if (p->engine.ps.lastf != TERMFONT_BOLD) {
			ps_pclose(p);
			ps_setfont(p, TERMFONT_BOLD);
		}
		p->engine.ps.last = c;
		return;
	} else {
		if (p->engine.ps.lastf != TERMFONT_NONE) {
			ps_pclose(p);
			ps_setfont(p, TERMFONT_NONE);
		}
		cc = p->engine.ps.last;
		p->engine.ps.last = c;
		c = cc;
	}

	ps_pletter(p, c);
}


static void
ps_advance(struct termp *p, size_t len)
{

	/*
	 * Advance some spaces.  This can probably be made smarter,
	 * i.e., to have multiple space-separated words in the same
	 * scope, but this is easier:  just close out the current scope
	 * and readjust our column settings.
	 */

	ps_fclose(p);
	p->engine.ps.pscol += len;
}


static void
ps_endline(struct termp *p)
{

	/* Close out any scopes we have open: we're at eoln. */

	ps_fclose(p);

	/*
	 * If we're in the margin, don't try to recalculate our current
	 * row.  XXX: if the column tries to be fancy with multiple
	 * lines, we'll do nasty stuff. 
	 */

	if (PS_MARGINS & p->engine.ps.flags)
		return;

	/* Left-justify. */

	p->engine.ps.pscol = p->engine.ps.left;

	/* If we haven't printed anything, return. */

	if (PS_NEWPAGE & p->engine.ps.flags)
		return;

	/*
	 * Put us down a line.  If we're at the page bottom, spit out a
	 * showpage and restart our row.
	 */

	if (p->engine.ps.psrow >= p->engine.ps.lineheight + 
			p->engine.ps.bottom) {
		p->engine.ps.psrow -= p->engine.ps.lineheight;
		return;
	}

	ps_closepage(p);
}


static void
ps_setfont(struct termp *p, enum termfont f)
{

	assert(f < TERMFONT__MAX);
	p->engine.ps.lastf = f;
	
	/*
	 * If we're still at the top of the page, let the font-setting
	 * be delayed until we actually have stuff to print.
	 */

	if (PS_NEWPAGE & p->engine.ps.flags)
		return;

	if (TERMTYPE_PS == p->type)
		ps_printf(p, "/%s %zu selectfont\n", 
				fonts[(int)f].name, 
				p->engine.ps.scale);
	else
		ps_printf(p, "/F%d %zu Tf\n", 
				(int)f, 
				p->engine.ps.scale);
}


/* ARGSUSED */
static size_t
ps_width(const struct termp *p, char c)
{

	if (c <= 32 || c - 32 >= MAXCHAR)
		return((size_t)fonts[(int)TERMFONT_NONE].gly[0].wx);

	c -= 32;
	return((size_t)fonts[(int)TERMFONT_NONE].gly[(int)c].wx);
}


static double
ps_hspan(const struct termp *p, const struct roffsu *su)
{
	double		 r;
	
	/*
	 * All of these measurements are derived by converting from the
	 * native measurement to AFM units.
	 */

	switch (su->unit) {
	case (SCALE_CM):
		r = PNT2AFM(p, su->scale * 28.34);
		break;
	case (SCALE_IN):
		r = PNT2AFM(p, su->scale * 72);
		break;
	case (SCALE_PC):
		r = PNT2AFM(p, su->scale * 12);
		break;
	case (SCALE_PT):
		r = PNT2AFM(p, su->scale * 100);
		break;
	case (SCALE_EM):
		r = su->scale *
			fonts[(int)TERMFONT_NONE].gly[109 - 32].wx;
		break;
	case (SCALE_MM):
		r = PNT2AFM(p, su->scale * 2.834);
		break;
	case (SCALE_EN):
		r = su->scale *
			fonts[(int)TERMFONT_NONE].gly[110 - 32].wx;
		break;
	case (SCALE_VS):
		r = su->scale * p->engine.ps.lineheight;
		break;
	default:
		r = su->scale;
		break;
	}

	return(r);
}

