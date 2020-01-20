/*
 * Based on https://github.com/tpoole2015/bernforth (jonesforth in C)
 * 2018 Konstantin Tcholokachvili
 * Public Domain
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <assert.h>

#ifdef DEBUG
#define P(x) printf(#x"\n");
#else
#define P(x)
#endif

/*
 * Types related
 */
typedef int64_t cell_t; // cell has to be large enough to hold the address of any variable

typedef enum {BLANK, COMMENT, WRITING} read_state;
typedef enum {F_NOTSET, F_IMMED = 2, F_HIDDEN = 4} word_flags;
typedef enum {EXECUTE, COMPILE} interpreter_state;

#define TOKEN_LENGTH 32
typedef struct
{
	char size;
	// unlike C strings Forth strings are not null terminated
	char buf[TOKEN_LENGTH];
} token_t;

typedef struct
{
	cell_t *prev;
	cell_t *cwp;
	char flags;
	token_t token;
} word_t;

typedef struct
{
	FILE *fp;
	cell_t *latest;
	cell_t *here;
	uint64_t cells_remaining;
} dictionary_t;

/*
 * Stack related
 */
#define INIT_STACK(x, type, size)	\
	type STACK_##x[(size)];		\
	const int SIZE_##x = (size);	\
	int TOP_##x = -1;		\

#define DSPTOP(x, ptr)		\
	ptr = STACK_##x;	\

#define DSPBOT(x, ptr)			\
	ptr = STACK_##x + TOP_##x;	\

#define PUSH(x, elem)							\
	if (TOP_##x == SIZE_##x - 1)					\
		fprintf(stderr, "ERROR:" #x " stack overflow\n");	\
	else								\
		STACK_##x[++TOP_##x] = (elem);				\

#define POP(x, elem)							\
	if (TOP_##x < 0)						\
		fprintf(stderr, "ERROR:" #x " stack underflow\n");	\
	else								\
		(elem) = STACK_##x[TOP_##x--];				\

#define PEAK(x, elem)			\
	(elem) = STACK_##x[TOP_##x];	\

/*
 * Memory related
 */
#define GET_FLAGPTR(addr) (char *)(addr + 1)

#define WRITE_BYTE(dst, x)		\
	*(char*)dst = (x);		\
	dst = (cell_t*)((char *)dst+1);	\

#define READ_BYTE(src, x)		\
	x = *(char*)src;		\
	src = (cell_t*)((char *)src+1);	\

#define WRITE_CELL(dst, x) *dst++ = (x);
#define READ_CELL(src, x) x = *src++;

cell_t
ALIGN8(cell_t x)
{
	return (x+7)&~(cell_t)7;
}

cell_t *
write_bytes(cell_t *dst, const char *bytes, const int n)
{
	memcpy(dst, bytes, n);
	return (cell_t *)((char *)dst + n);
}

cell_t *
read_bytes(const cell_t *src, char *bytes, const int n)
{
	memcpy(bytes, src, n);
	return (cell_t *)((char *)src + n);
}

cell_t *
write_word(cell_t *dst, const word_t *w)
{
	WRITE_CELL(dst, (cell_t)w->prev)
	WRITE_BYTE(dst, w->flags)
	WRITE_BYTE(dst, w->token.size)
	dst = write_bytes(dst, w->token.buf, (int)w->token.size);
	return (cell_t *)ALIGN8((cell_t)dst);
}

cell_t *
read_word(const cell_t *src, word_t *w)
{
	cell_t c;
	READ_CELL(src, c)
	w->prev = (cell_t *)c;
	READ_BYTE(src, w->flags)
	READ_BYTE(src, w->token.size)
	src = read_bytes(src, (char *)w->token.buf, (int)w->token.size);
	return (cell_t *)ALIGN8((cell_t)src);
}

/*
 * Token related
 */
#define FORTH_COMMENT '\\'

void
token_init(token_t *t)
{
	memset(t->buf, 0, TOKEN_LENGTH);
	t->size = 0;
}

void
token_copy(token_t *dst, const char *src, const unsigned int size)
{
	memcpy(dst->buf, src, size);
	dst->size = size;
}

bool
token_cmp(const token_t *lhs, const token_t *rhs)
{
	return ((lhs->size == rhs->size) && !memcmp(lhs->buf, rhs->buf, lhs->size)) ? true : false;
}

bool
token_tonum(const token_t *t, const unsigned int base, int64_t *n)
{
	char str[TOKEN_LENGTH+1] = {0};
	memcpy(str, t->buf, t->size);
	const int64_t x = strtoll(str, NULL, base);
	if (!x && str[0] != '0')
		return false;
	*n = x;
	return true;
}

unsigned int
token_get_next(FILE *fp, token_t *token)
{
	read_state state = BLANK;
	char c;

	token_init(token);

	while ((c = fgetc(fp)) != EOF)
	{
		switch (state)
		{
			case COMMENT:
				{
					if (c == '\n')
						state = BLANK;
					break;
				}
			case BLANK:
				{
					if (c == FORTH_COMMENT)
						state = COMMENT;
					else if (!(c == ' ' || c == '\t' || c == '\n'))
						state = WRITING;
					break;
				}
			case WRITING:
				{
					if (c == ' ' || c == '\t' || c == '\n')
					{
						return token->size; // finished reading token
					}
					break;
				}
		};

		if (state == WRITING)
			token->buf[token->size++] = c;
	}

	return token->size;
}

/*
 * Dictionary related
 */
#define DICT_INIT_SIZE_CELLS 65536

bool
dict_init(dictionary_t *dictionary, const char *fn)
{
	dictionary->here = (cell_t *)malloc(DICT_INIT_SIZE_CELLS * sizeof(cell_t));
	if (!dictionary->here)
	{
		fprintf(stderr, "Error allocating memory for dictionary.\n");
		return false;
	}

	dictionary->latest = NULL;
	dictionary->cells_remaining = DICT_INIT_SIZE_CELLS;

	// open file where we'll write the contents of the dictionary to
	if ( (dictionary->fp = fopen(fn, "w")) == NULL)
	{
		fprintf(stderr, "error opening file %s\n", fn);
		return false;
	}

	return true;
}

cell_t *
dict_lookup_word(const dictionary_t *dictionary, const token_t *t, word_t *w)
{
	cell_t *cur = dictionary->latest;
	while (cur)
	{
		w->cwp = read_word(cur, w);
		if (!(w->flags & F_HIDDEN) && token_cmp(t, &(w->token)))
			return cur;
		cur = w->prev;
	}

	return NULL;
}

cell_t *
dict_append_word(dictionary_t *dictionary, const char flags, const token_t *token)
{
#define CELLS_PER_WORD sizeof(word_t)/sizeof(cell_t)
	assert(dictionary->cells_remaining > CELLS_PER_WORD);
	word_t w;
	w.prev = dictionary->latest;
	w.flags = flags;
	w.token = *token;

	dictionary->latest = dictionary->here;
	dictionary->here = write_word(dictionary->here, &w);
	dictionary->cells_remaining -= (dictionary->here - dictionary->latest);

	char str[TOKEN_LENGTH+1] = {0};
	memcpy(str, token->buf, token->size);
	fprintf(dictionary->fp, "%lX:%s\n", (int64_t)dictionary->here, str);

	return dictionary->here;
}

void
dict_append_cell(dictionary_t *dictionary, const cell_t data)
{
	*(dictionary->here) = data;
	fprintf(dictionary->fp, "%lX:%ld\n", (int64_t)dictionary->here, (int64_t)data);

	++dictionary->here;
	--dictionary->cells_remaining;
}

/*
 * Main code
 */
#define STACK_SIZE 100

dictionary_t dictionary;
#define ADD_ATOMIC(label, buf, flags)\
cell_t *CWP_##label;                        \
{                                         \
	const token_t t = {(char)(sizeof(buf)-1), buf};\
	CWP_##label = dict_append_word(&dictionary, flags, &t); \
	dict_append_cell(&dictionary, (cell_t)&&label);    \
}                                         \

#define COMMA(x) dict_append_cell(&dictionary, (cell_t)x);
#define CWP(x) dict_append_cell(&dictionary, (cell_t)CWP_##x);

int
main(int argc, char *argv[])
{
	token_t itok; // latest token read by INTERPRET
	token_t wtok; // latest token read by WORD
	word_t w;     // last word looked up
	cell_t a, b, c, d; // temporary registers
	cell_t *W; // working register
	cell_t *IP; // interpreter pointer
	cell_t base = 10;
	cell_t state = EXECUTE;

	INIT_STACK(RS, cell_t, STACK_SIZE)
	INIT_STACK(PS, cell_t, STACK_SIZE)

	if (!dict_init(&dictionary, ".jforth_dict"))
		return 1;

	ADD_ATOMIC(ADD, "+", F_NOTSET)
	ADD_ATOMIC(BASE, "BASE", F_NOTSET)
	ADD_ATOMIC(BRANCH, "BRANCH", F_NOTSET)
	ADD_ATOMIC(BRANCHCOND, "0BRANCH", F_NOTSET)
	ADD_ATOMIC(CHAR, "CHAR", F_NOTSET)
	ADD_ATOMIC(CREATE, "CREATE", F_NOTSET)
	ADD_ATOMIC(COMMA, ",", F_NOTSET)
	ADD_ATOMIC(DIVMOD, "/MOD", F_NOTSET)
	ADD_ATOMIC(DOCOL, "DOCOL", F_NOTSET)
	ADD_ATOMIC(DROP, "DROP", F_NOTSET)
	ADD_ATOMIC(TWODROP, "2DROP", F_NOTSET)
	ADD_ATOMIC(DUP, "DUP", F_NOTSET)
	ADD_ATOMIC(EMIT, "EMIT", F_NOTSET)
	ADD_ATOMIC(EXIT, "EXIT", F_NOTSET)
	ADD_ATOMIC(FETCH, "@", F_NOTSET)
	ADD_ATOMIC(FIND, "FIND", F_NOTSET)
	ADD_ATOMIC(HERE, "HERE", F_NOTSET)
	ADD_ATOMIC(HIDE, "HIDE", F_NOTSET)
	ADD_ATOMIC(HIDDEN, "HIDDEN", F_NOTSET)
	ADD_ATOMIC(IMMEDIATE, "IMMEDIATE", F_IMMED)
	ADD_ATOMIC(INTERPRET, "INTERPRET", F_NOTSET)
	ADD_ATOMIC(LATEST, "LATEST", F_NOTSET)
	ADD_ATOMIC(LBRAC, "[", F_IMMED)
	ADD_ATOMIC(LIT, "LIT", F_NOTSET)
	ADD_ATOMIC(MUL, "*", F_NOTSET)
	ADD_ATOMIC(OVER, "OVER", F_NOTSET)
	ADD_ATOMIC(RBRAC, "]", F_NOTSET)
	ADD_ATOMIC(STORE, "!", F_NOTSET)
	ADD_ATOMIC(SUB, "-", F_NOTSET)
	ADD_ATOMIC(SWAP, "SWAP", F_NOTSET)
	ADD_ATOMIC(TWOSWAP, "2SWAP", F_NOTSET)
	ADD_ATOMIC(TOCFA, ">CFA", F_NOTSET)
	ADD_ATOMIC(WORD, "WORD", F_NOTSET)
	ADD_ATOMIC(ZEQU, "0=", F_NOTSET)
	ADD_ATOMIC(GT, ">", F_NOTSET)
	ADD_ATOMIC(GTEQ, ">=", F_NOTSET)
	ADD_ATOMIC(LT, "<", F_NOTSET)
	ADD_ATOMIC(LTEQ, "<=", F_NOTSET)
	ADD_ATOMIC(EQ, "=", F_NOTSET)
	ADD_ATOMIC(NEQ, "<>", F_NOTSET)
	ADD_ATOMIC(KEY, "KEY", F_NOTSET)
	ADD_ATOMIC(DSPBOT, "DSP@", F_NOTSET)
	ADD_ATOMIC(DSPTOP, "DSP0", F_NOTSET)
	ADD_ATOMIC(ROT, "ROT", F_NOTSET)
	ADD_ATOMIC(NROT, "-ROT", F_NOTSET)
	ADD_ATOMIC(AND, "AND", F_NOTSET)
	ADD_ATOMIC(OR, "OR", F_NOTSET)
	ADD_ATOMIC(XOR, "XOR", F_NOTSET)
	ADD_ATOMIC(INVERT, "INVERT", F_NOTSET)
	ADD_ATOMIC(STATE, "STATE", F_NOTSET)
	ADD_ATOMIC(CSTORE, "C!", F_NOTSET)
	ADD_ATOMIC(CFETCH, "C@", F_NOTSET)
	ADD_ATOMIC(TWODUP, "2DUP", F_NOTSET)
	ADD_ATOMIC(LITSTRING, "LITSTRING", F_NOTSET)
	ADD_ATOMIC(TELL, "TELL", F_NOTSET)
	ADD_ATOMIC(FIMMED, "F_IMMED", F_NOTSET)
	ADD_ATOMIC(FHIDDEN, "F_HIDDEN", F_NOTSET)
	ADD_ATOMIC(TOR, ">R", F_NOTSET)
	ADD_ATOMIC(FROMR, "R>", F_NOTSET)
	ADD_ATOMIC(DOT, ".", F_NOTSET)
	ADD_ATOMIC(ONEPLUS, "1+", F_NOTSET)
	ADD_ATOMIC(ONEMINUS, "1-", F_NOTSET)
	ADD_ATOMIC(CMOVE, "CMOVE", F_NOTSET)


// : QUIT INTERPRET BRANCH -2 ;
	const token_t quit = {4, "QUIT"};
	dict_append_word(&dictionary, F_NOTSET, &quit);
	COMMA(&&DOCOL)
	CWP(INTERPRET)
	CWP(BRANCH)
	COMMA(-2) // go back 2 cells

	FILE *fp = stdin;
	if (argc > 1)
	{
		if ( (fp = fopen(argv[1], "r")) == NULL)
		{
			fprintf(stderr, "error opening file %s\n", argv[1]);
			fp = stdin;
		}
		else
			printf("loading file %s\n", argv[1]);
	}
#define PROCESS_EOF			\
	if (fp == stdin) {		\
		printf("GOOD BYE\n");	\
		return 0;		\
	}				\
	printf("loaded!\n");		\
	fp = stdin;			\
	goto main_loop;			\

main_loop:

// Every atomic word implemented has to end in NEXT
#define NEXT			\
	W = (cell_t *)*IP++;	\
	goto *(void *)*W;	\

	// Start by running the QUIT word
	dict_lookup_word(&dictionary, &quit, &w);
	IP = w.cwp;
	W = IP;
	goto *(void *)(*(cell_t *)W);

TOR: // ( n -- )  RS: ( -- n )
	P(>R)
	POP(PS, a)
	PUSH(RS, a)
	NEXT

FROMR: // ( -- n )  RS: ( n --  )
	P(R>)
	POP(RS, a)
	PUSH(PS, a)
	NEXT

FIMMED: // ( -- )
	P(FIMMED)
	PUSH(PS, (cell_t)F_IMMED)
	NEXT

FHIDDEN: // ( -- )
	P(FHIDDEN)
	PUSH(PS, (cell_t)F_HIDDEN)
	NEXT

TELL: // ( addr len -- )
	P(TELL)
	POP(PS, a) // a = len
	POP(PS, b) // b = addr
	write(1, (char *)b, a);
	NEXT

LITSTRING: // ( -- addr len )
	P(LITSTRING)
	{
		const uint64_t byte_len = *IP++; // length of string in bytes
		PUSH(PS, (cell_t)IP)
		IP += ALIGN8(byte_len);
		PUSH(PS, (cell_t)byte_len)
	}
	NEXT

TWODUP: // 2DUP ( a b -- a b a b )
	P(2DUP)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a)
	PUSH(PS, b)
	PUSH(PS, a)
	PUSH(PS, b)
	NEXT

CFETCH: // C@ ( addr -- char )
	P(C@)
	POP(PS, a)
	{
		char * const c = (char *)a;
		PUSH(PS, (cell_t)*c)
	}
	NEXT

CSTORE: // C! ( char addr -- )
	P(C!)
	POP(PS, a) // a = addr
	POP(PS, b) // b = char
	{
		char * const c = (char *)a;
		*c = (char)b;
	}
	NEXT

STATE: // ( -- addr )
	P(STATE)
	PUSH(PS, (cell_t)&state)
	NEXT

INVERT: // ( a -- ~a )
	P(AND)
	POP(PS, a)
	PUSH(PS, ~a)
	NEXT

OR: // ( a b -- a|b )
	P(AND)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a|b)
	NEXT

AND: // ( a b -- a&b )
	P(AND)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a&b)
	NEXT

NROT: // ( c b a -- a c b )
	P(-ROT)
	POP(PS, a)
	POP(PS, b)
	POP(PS, c)
	PUSH(PS, a)
	PUSH(PS, c)
	PUSH(PS, b)
	NEXT

ROT : // ( a b c -- b c a )
	P(ROT)
	POP(PS, c)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, b)
	PUSH(PS, c)
	PUSH(PS, a)
	NEXT

LTEQ: // <= ( a b -- a<=b)
	P(GT)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, (cell_t)(a<=b))
	NEXT

GTEQ: // >= ( a b -- a>=b)
	P(GT)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, (cell_t)(a>=b))
	NEXT

KEY: // ( -- char )
	P(KEY)
	{
		const char c = fgetc(fp);
		if (c == EOF)
		{
			PROCESS_EOF
		}
		PUSH(PS, (cell_t)c)
	}
	NEXT

DSPTOP: // DSP0 ( -- addr )
	P(DSP0)
	{
		cell_t *sp;
		DSPTOP(PS, sp)
		PUSH(PS, (cell_t)sp)
	}
	NEXT

DSPBOT: // DSP@ ( -- addr )
	P(DSP@)
	{
		cell_t *sp;
		DSPBOT(PS, sp)
		PUSH(PS, (cell_t)sp)
	}
	NEXT

EQ: // ( a b -- a==b )
	P(EQ)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, (cell_t)(a==b))
	NEXT

NEQ: // ( a b -- a!=b )
	P(NEQ)
	POP(PS, a)
	POP(PS, b)
	PUSH(PS, (cell_t)(a!=b))
	NEXT


LT: // < ( a b -- a<b)
	P(LT)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, (cell_t)(a<b))
	NEXT

ADD: // + ( a b -- a+b )
	P(ADD)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a+b)
	NEXT

BASE: // ( -- addr )
	P(BASE)
	PUSH(PS, (cell_t)&base)
	NEXT

BRANCH: // ( -- )
	P(BRANCH)
	/*
	 * IP points to the branch offset.
	 * i.e. our dictionary looks as follows
	 * ... | BRANCH | offset | ...
	 * 			 ^
	 * 			 |
	 * 			 IP
	 */
	IP += *IP;
	NEXT

BRANCHCOND: // 0BRANCH ( a -- )
	P(BRANCHCOND)
	POP(PS, a)
	IP += a ? 1 /* skip offset */ : *IP;
	NEXT

CHAR: // ( -- char) word
	P(CHAR)
	if (!token_get_next(fp, &wtok))
	{
		PROCESS_EOF
	}
	PUSH(PS, (cell_t)wtok.buf[0])
	NEXT

COMMA: // , ( a -- )
	P(COMMA)
	POP(PS, a)
	dict_append_cell(&dictionary, a);
	NEXT

CREATE: // CREATE ( addr len -- )
	P(CREATE)
	POP(PS, a) // a = len
	POP(PS, b) // b = address
	{
		token_t token;
		token_copy(&token, (char *)b, (unsigned int)a);
		dict_append_word(&dictionary, F_NOTSET, &token);
		COMMA(&&DOCOL)
	}
	NEXT

DIVMOD: // ( a b -- a%b a/b )
	P(DIVMOD)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a%b)
	PUSH(PS, (cell_t)(a/b))
	NEXT

DOCOL:
	P(DOCOL)
	PUSH(RS, (cell_t)IP)
	IP = ++W;
	NEXT

DROP: // ( a -- )
	P(DROP)
	POP(PS, a)
	NEXT

TWODROP: // ( a -- )
	P(2DROP)
	POP(PS, a)
	POP(PS, a)
	NEXT


DUP: // ( a -- a a )
	P(DUP)
	PEAK(PS, a)
	PUSH(PS, a)
	NEXT

EMIT: // ( char -- )
	P(EMIT)
	POP(PS, a);
	write(1, (char *)&a, 1);
	NEXT

EXIT:
	P(EXIT)
	POP(RS, a);
	IP = (cell_t *)a;
	NEXT

FETCH: // @ ( addr -- n )
	P(FETCH)
	POP(PS, a)
	PUSH(PS, (cell_t)(*(cell_t *)a))
	NEXT

FIND: // ( len addr -- addr )
	P(FIND)
	POP(PS, a); // a = addr
	POP(PS, b); // b = len
	{
		token_t t;
		token_copy(&t, (char *)b, (unsigned int)a);
		PUSH(PS, (cell_t)(dict_lookup_word(&dictionary, &t, &w)))
	}
	NEXT

GT: // > ( a b -- a>b)
	P(GT)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, (cell_t)(a>b))
	NEXT

HERE: // ( -- addr )
	P(HERE)
	PUSH(PS, (cell_t)&(dictionary.here))
	NEXT

HIDE: // ( -- )
	P(HIDE)
	{
		char *flag_ptr = GET_FLAGPTR(dictionary.latest);
		*flag_ptr ^= F_HIDDEN;
	}
	NEXT

HIDDEN: // ( addr -- )
	P(HIDDEN)
	POP(PS, a)
	{
		char *flag_ptr = GET_FLAGPTR((cell_t *)a);
		*flag_ptr ^= F_HIDDEN;
	}
	NEXT

IMMEDIATE: // ( -- )
	P(IMMEDIATE)
	{
		char *flag_ptr = GET_FLAGPTR(dictionary.latest);
		*flag_ptr ^= F_IMMED;
	}
	NEXT

INTERPRET: // ( -- )
	P(INTERPRET)
	get_next_word:
	{
		if (!token_get_next(fp, &itok))
		{
			PROCESS_EOF
		}

		char str[TOKEN_LENGTH+1] = {0};
		memcpy(str, itok.buf, itok.size);

		bool islit = false;
		word_t w;
		int64_t n;

		if (!dict_lookup_word(&dictionary, &itok, &w))
		{
			// word not in dictionary
			if (!token_tonum(&itok, base, &n))
			{
				fprintf(stderr, "ERROR: couldn't parse %s\n", str);
				goto get_next_word;
			}

			islit = true;
			if (EXECUTE == state)
			{
				PUSH(PS, (cell_t)n)
				NEXT
			}
		}
		else
		{
			// found word in dictionary
			W = w.cwp;
			if (state == EXECUTE || (w.flags & F_IMMED))
			{
				if (state == COMPILE) fprintf(dictionary.fp, "%s\n", str);
					goto *(void *)*W; // word has to be executed immediately
			}
		}

		P(COMPILING)
		if (islit)
		{
			fprintf(dictionary.fp, "LIT ");
			CWP(LIT)
			fprintf(dictionary.fp, "%ld ", n);
			COMMA(n)
		}
		else
		{
			fprintf(dictionary.fp, "%s ", str);
			COMMA(W)
		}
		NEXT
	}

LBRAC: // [ ( -- )
	P(LBRAC)
	state = EXECUTE;
	NEXT

LATEST: // ( -- addr )
	P(LATEST)
	PUSH(PS, (cell_t)&(dictionary.latest))
	NEXT

LIT: // ( -- *IP )
	P(LIT)
	PUSH(PS, *IP)
	++IP;
	NEXT

MUL: // * ( a b -- a*b )
	P(MUL)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a*b)
	NEXT

OVER: // ( a b -- a b a )
	P(OVER)
	POP(PS, b)
	PEAK(PS, a)
	PUSH(PS, b)
	PUSH(PS, a)
	NEXT

RBRAC: // ] ( -- )
	P(RBRAC)
	state = COMPILE;
	NEXT

STORE: // ! ( n addr -- )
	P(STORE)
	POP(PS, a) // a = addr
	POP(PS, b) // b = n
	*(cell_t *)a = b;
	NEXT

SUB: // - ( a b -- a-b )
	P(SUB)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a - b)
	NEXT

SWAP: // ( a b -- b a )
	P(SWAP)
	POP(PS, b)
	POP(PS, a)
	PUSH(PS, a)
	PUSH(PS, b)
	NEXT

TWOSWAP: // ( a b c d -- b a d c )
	P(2SWAP)
	POP(PS, a)
	POP(PS, b)
	POP(PS, c)
	POP(PS, d)
	PUSH(PS, b)
	PUSH(PS, a)
	PUSH(PS, d)
	PUSH(PS, c)
	NEXT

TOCFA: // >CFA ( addr -- addr )
	P(TOCFA)
	POP(PS, a)
	PUSH(PS, (cell_t)(read_word((cell_t *)a, &w)))
	NEXT

WORD: // ( -- addr len ) word
	P(WORD)
	if (!token_get_next(fp, &wtok))
	{
		PROCESS_EOF
	}
	PUSH(PS, (cell_t)wtok.buf)
	PUSH(PS, (cell_t)wtok.size)
	NEXT

ZEQU: // ( a -- !a )
	P(ZEQU)
	POP(PS, a)
	PUSH(PS, !a)
	NEXT

DOT:
	P(DOT)
	POP(PS, a)
	fprintf(stdout, "%ld ", a);
	NEXT

ONEPLUS: // ( a -- a+1 )
	P(ONEPLUS)
	POP(PS, a)
	PUSH(PS, a+1)
	NEXT

ONEMINUS: // ( a -- a-1 )
	P(ONEMINUS)
	POP(PS, a)
	PUSH(PS, a-1)
	NEXT

XOR: // ( a b -- a^b )
	P(XOR)
	POP(PS, a)
	POP(PS, b)
	PUSH(PS, a^b)
	NEXT

CMOVE: // (addr1 addr2 u -- )
	P(CMOVE)
	POP(PS, c)
	POP(PS, b)
	POP(PS, a)
	memcpy((void *)b, (void *)a, c);
	NEXT
}
