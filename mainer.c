/*
 * note, protocol described at
 *    https://github.com/str4d/zips/blob/77-zip-stratum/drafts/str4d-stratum/draft1.rst
 * is not compatible with some pools, for example with zcash.flypool.org
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <poll.h>
#include <errno.h>
#include <time.h>

#include "jsmn/jsmn.h"
#include "sha256/sha256.h"
#include "blake2b.h"
#include "equihash.h"

#define VERSION			"04000000"
#define BUF_SIZE		4096
#define JSON_TOKENS_MAX		64
#define TIME_STAT_PERIOD	15

static char			pool_host[BUF_SIZE] = "127.0.0.1";
static int			pool_port = 3333;
static char			miner_name[BUF_SIZE] = "yazecminer";
static char			worker_name[BUF_SIZE] =
 				    "t1PsxqaQ1o5PDTALJN2Fn8BxeBvcpQyqKwV";
static char			worker_pass[BUF_SIZE] = "x";
static int			flag_bench = 0;
static int			flag_debug = 0;

static int			sock_fh = -1;
static char			out_buf[BUF_SIZE + 1];
static int			out_pos = 0;
static int			out_len = 0;
static char			in_buf[BUF_SIZE + 1];
static int			in_len = 0;

static jsmntok_t		json_token[JSON_TOKENS_MAX];
static int			json_tokens;

static int			jsonrpc_id;
static block_t			block = { 0 };
static int			nonce1_len = 0;
static char			job_id[BUF_SIZE];
static uint8_t			target[SHA256_DIGEST_SIZE] = { 0 };
static int			flag_new_job = 0;
static time_t			time_start;
static time_t			time_last;
static time_t			time_prev;

static int			stat_jobs = 0;
static int			stat_found = 0;
static int			stat_interrupts = 0;
static int			stat_submitted = 0;
static int			stat_accepted = 0;
static int			stat_found_last = 0;
static int			stat_found_cur = 0;

#define JSONRPC_ID_SUBSCRIBE	1
#define JSONRPC_ID_AUTHORIZE	2
#define JSONRPC_ID_EXTRANONCE	3
#define JSON_FIRST_CHAR(t)	in_buf[ json_token[t].start ]

static void			send_authorize (void);
static void			send_extranonce (void);

static void
Log (char *fmt, ...) {
	time_t			t;
	static char		buf[30];
	struct tm		*tm_info;
	va_list			ap;

	time (&t);
	tm_info = localtime (&t);
	strftime (buf, sizeof (buf), "%Y-%m-%d %H:%M:%S", tm_info);
	printf ("%s ", buf);

	va_start (ap, fmt);
	vfprintf (stdout, fmt, ap);
	va_end (ap);

	printf ("\n");
	fflush (stdout);
}

static void
die (char *str) {
	if (str[0] == '!') {
		str++;
		printf ("error %d (%s), ", errno, strerror (errno));
	}
	printf ("%s, exiting\n", str);
	exit (1);
}

static void
unhex (unsigned char *dst, int len, char *src) {
	int		i, j, c[2];

	for (i = 0; i < len; i++) {
		for (j = 0; j < 2; j++) {
			c[j] =
			     *src >= '0' && *src <= '9' ? *src - '0' :
			     *src >= 'A' && *src <= 'F' ? *src - 'A' + 10 :
			     *src >= 'a' && *src <= 'f' ? *src - 'a' + 10 : -1;
			if (c[j] < 0)
				die ("not a hex digit");
			src++;
		}
		dst[i] = (c[0] << 4) | c[1];
	}
	if (*src)
		die ("hex length does not match");
}

static void
hex (char *dst, unsigned char *src, int len) {
	int		i;
	static char	h[] = "0123456789abcdef";

	for (i = 0; i < len; i++) {
		*dst++ = h[src[i] >> 4];
		*dst++ = h[src[i] & 15];
	}
	*dst = 0;
}

static char *
json_string (int t) {
	if (json_token[t].type != JSMN_STRING)
		die ("not a string");
	in_buf[ json_token[t].end ] = 0;
	return &JSON_FIRST_CHAR(t);
}

static int
json_is_string (int t, char *str) {
	return !strcmp (json_string (t), str);
}

static void
recv_target (void) {
	if (json_token[6].size != 1)
		die ("mining.target params size is not 1");

	unhex (target, SHA256_DIGEST_SIZE, json_string (7));
	Log ("got target %s", &JSON_FIRST_CHAR (7));

	send_extranonce ();
}

static void
recv_job (void) {
	if (json_token[6].size != 8)
		die ("mining.notify params size is not 8");

	if (!json_is_string (8, VERSION))
		die ("mining.notify bad version");

	strncpy (job_id, json_string (7), BUF_SIZE);

	unhex (block.version,    sizeof (block.version),    json_string (8));
	unhex (block.prevhash,   sizeof (block.prevhash),   json_string (9));
	unhex (block.merkleroot, sizeof (block.merkleroot), json_string (10));
	unhex (block.reserved,   sizeof (block.reserved),   json_string (11));
	unhex (block.time,       sizeof (block.time),       json_string (12));
	unhex (block.bits,       sizeof (block.bits),       json_string (13));

	if (json_token[14].type != JSMN_PRIMITIVE)
	    die ("mining.notify bad clean_jobs");

	Log ("new job %s", job_id);
	stat_jobs++;
	flag_new_job = 1;
}

static void
recv_subscribed (void) {
	char		*nonce1;

	if (json_token[4].type != JSMN_ARRAY ||
	    json_token[4].size != 2)
		die ("bad subscribe response");

	nonce1 = json_string (6);
	nonce1_len = strlen (nonce1) / 2;
	if (nonce1_len >= (int)sizeof (block.nonce))
		die ("nonce1 is too big");
	unhex (block.nonce, nonce1_len, nonce1);

	Log ("subscribed, session id is %s, nonce1 %s len %d",
	    json_string (5), nonce1, nonce1_len);

	send_authorize ();
}

static void
recv_authorized (void) {
	if (json_token[4].type != JSMN_PRIMITIVE ||
	    JSON_FIRST_CHAR (4) != 't')
		die ("not authorized");

	Log ("authorized");
}

static void
json_do_notification (void) {
	if (!json_is_string (3, "method"))
		die ("notify has no method");

	if (!json_is_string (5, "params"))
		die ("notify has no params");
	if (json_token[6].type != JSMN_ARRAY)
		die ("notify param is not array");

	if (json_is_string (4, "mining.target") ||
	    json_is_string (4, "mining.set_target")) {
		recv_target ();
	} else if (json_is_string (4, "mining.notify")) {
		recv_job ();
	} else {
		die ("bad notify method");
	}
}

static void
json_do_response (void) {
	int		i = 5, id;

	id = atoi (&JSON_FIRST_CHAR (2));

	if (!json_is_string (3, "result"))
		die ("not a result");

	if (json_token[4].type == JSMN_ARRAY) {
		for (i = 5; i < 5 + json_token[4].size; i++)
			if (json_token[i].type != JSMN_PRIMITIVE &&
			    json_token[i].type != JSMN_STRING)
				die ("result array is complex");
	} else if (json_token[4].type != JSMN_PRIMITIVE) {
		die ("result is not an array or primitive\n");
	}

	if (json_token[0].size >= 3 && 
	    !json_is_string (i, "error") &&
	    (json_token[i + 1].type != JSMN_PRIMITIVE ||
	    JSON_FIRST_CHAR (i + 1) != 'n'))
		die ("XXX response error");

	if (id == JSONRPC_ID_SUBSCRIBE) {
		recv_subscribed ();
	} else if (id == JSONRPC_ID_AUTHORIZE) {
		recv_authorized ();
	} else if (id == JSONRPC_ID_EXTRANONCE) {
		die ("extranonce response unexpected");
	} else {
		if (json_token[4].type != JSMN_PRIMITIVE ||
		    JSON_FIRST_CHAR (4) != 't')
			die ("not accepted");
		Log ("submit %d accepted", id);
		stat_accepted++;
	}
}

static void
json_do (void) {
	int		i;

	for (i = 0; flag_debug > 2 && i < json_tokens; i++)
		printf ("token %d: %s, start %d '%c' end %d '%c' size %d\n", i,
		    json_token[i].type == JSMN_PRIMITIVE? "primitive" :
		    json_token[i].type == JSMN_OBJECT	? "object" :
		    json_token[i].type == JSMN_ARRAY	? "array" :
		    json_token[i].type == JSMN_STRING	? "string" : "???",
		    json_token[i].start, JSON_FIRST_CHAR (i),
		    json_token[i].end, in_buf[ json_token[i].end ],
		    json_token[i].size);

	/*
	 * we expect only notifications
	 *   { id:null, method:"", params:[] }
	 * or responses
	 *   { id:1, result:[], error:null }
	 */
	if (json_token[0].type != JSMN_OBJECT)
		die ("first token is not an object");
	if (json_token[0].size < 2)
		die ("expecting at least two keys in top object");
	if (!json_is_string (1, "id"))
		die ("expecting first key 'id'");
	if (json_token[2].type != JSMN_PRIMITIVE)
		die ("'id' value is not primitive");

	if (JSON_FIRST_CHAR (2) == 'n' ||
	    JSON_FIRST_CHAR (2) == '0')
		json_do_notification ();
	else if (JSON_FIRST_CHAR (2) >= '1' && JSON_FIRST_CHAR (2) <= '9')
		json_do_response ();
	else
		die ("'id' value is boolean?");
}

static void
json_parse (void) {
	jsmn_parser	parser;
	char		*p;

	if (flag_debug > 2)
		printf ("json_parse\n");

	p = strchr (in_buf, '\n');
	if (!p)
		return;
	*p = 0;

	jsmn_init (&parser);
	json_tokens = jsmn_parse (&parser, in_buf, p - in_buf, json_token,
	    JSON_TOKENS_MAX);
	switch (json_tokens) {
	case JSMN_ERROR_INVAL:
		die ("corrupted json");
	case JSMN_ERROR_NOMEM:
		die ("too many tokens");
	case JSMN_ERROR_PART:
		return;
	case 0:
		die ("zero json tokens?");
	}

	json_do ();

	in_len -= json_token[0].end + 1;
	memmove (in_buf, p + 1, in_len);
	in_buf[in_len] = 0;

	json_parse ();	/* in case of another json in buffer */
}

static void
sock_open (void) {
	struct sockaddr_in	si;
	struct hostent		*he;

	he = gethostbyname (pool_host);
	if (!he)
		die ("no host");

	sock_fh = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock_fh < 0)
		die ("!socket");

	si.sin_family = AF_INET; 
	memcpy (&si.sin_addr, he->h_addr_list[0], he->h_length);
	si.sin_port = htons (pool_port);

	if (connect (sock_fh, (struct sockaddr *)&si, sizeof (si)) < 0)
		die ("!connect failed");
}

static void
sock_send (char *str, int len) {
	if (out_len + len > BUF_SIZE)
		die ("send overflow");
	memcpy (out_buf + out_len, str, len);
	out_len += len;
	out_buf[out_len] = 0;
}

static void
send_subscribe (void) {
	char		buf[BUF_SIZE];

	snprintf (buf, BUF_SIZE - 1,
	    "{\"id\":%d,\"method\":\"mining.subscribe\",\"params\":"
	    "[\"%s\",null,\"%s\",%d]}\n",
	    (jsonrpc_id = JSONRPC_ID_SUBSCRIBE),
	    miner_name, pool_host, pool_port);

	sock_send (buf, strlen (buf));
}

static void
send_authorize (void) {
	char		buf[BUF_SIZE];

	snprintf (buf, BUF_SIZE - 1,
	    "{\"id\":%d,\"method\":\"mining.authorize\",\"params\":"
	    "[\"%s\",\"%s\"]}\n",
	    (jsonrpc_id = JSONRPC_ID_AUTHORIZE),
	    worker_name, worker_pass);

	sock_send (buf, strlen (buf));
}

static void
send_extranonce (void) {
	char		buf[BUF_SIZE];

	snprintf (buf, BUF_SIZE - 1,
	    "{\"id\":%d,\"method\":\"mining.extranonce.subscribe\",\"params\":"
	    "[]}\n",
	    (jsonrpc_id = JSONRPC_ID_EXTRANONCE));

	sock_send (buf, strlen (buf));
}

static void
send_submit (char *job_time, char *nonce_2, char *sol) {
	char		buf[BUF_SIZE];

	snprintf (buf, BUF_SIZE - 1,
	    "{\"id\":%d,\"method\":\"mining.submit\",\"params\":"
	    "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]}\n",
	    ++jsonrpc_id, worker_name, job_id, job_time, nonce_2, sol);

	sock_send (buf, strlen (buf));
}

int
above_target (void) {
	int		i;
	uint8_t		diff[SHA256_DIGEST_SIZE];

	sha256 ((uint8_t *)&block, sizeof (block), diff);
	sha256 (diff, SHA256_DIGEST_SIZE, diff);

	if (flag_debug > 1) {
		printf ("sol difficulty ");
		for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
			printf ("%02x", diff[SHA256_DIGEST_SIZE - 1 - i]);
		}
		printf ("\n");
	}

	for (i = 0; i < SHA256_DIGEST_SIZE; i++) {
		if (diff[SHA256_DIGEST_SIZE - 1 - i] < target[i])
			return 0;
		if (diff[SHA256_DIGEST_SIZE - 1 - i] > target[i])
			return 1;
	}
	die ("diffculty equals target");
	return -1;
}

int
solution (void) {
	char		nonce2[BUF_SIZE];
	char		solution[BUF_SIZE];
	char		job_time[sizeof (block.time) * 2 + 1];

	stat_found++;
	stat_found_cur++;
	if (above_target ()) {
		if (flag_debug)
			printf ("above target\n");
		return 0;
	}

	hex (job_time, block.time, sizeof (block.time));
	hex (nonce2, block.nonce + nonce1_len,
	    sizeof (block.nonce) - nonce1_len);
	hex (solution, block.solsize,
	    sizeof (block.solsize) + sizeof (block.solution));
	send_submit (job_time, nonce2, solution);
	stat_submitted++;

	Log ("solution to %s submitted", job_id);
	return 1;
}

static void
periodic (int timeout) {
	struct pollfd		pfd;
	int			i;

	pfd.fd = sock_fh;
	pfd.events = POLLIN;
	if (out_len)
		pfd.events |= POLLOUT;

	if (poll (&pfd, 1, timeout) < 0)
		die ("!poll");

	if (pfd.revents & POLLIN) {
		i = recv (sock_fh, in_buf + in_len, BUF_SIZE - in_len, 0);
		if (i < 0)
			die ("!recv");
		if (i == 0)
			die ("zero recv, socket was closed?");
		in_len += i;
		if (in_len > BUF_SIZE)
			die ("wtf");
		in_buf[in_len] = 0;
		if (flag_debug)
			printf ("in buffer: %s", in_buf);
		json_parse ();
	}
	if (pfd.revents & POLLOUT) {
		if (flag_debug)
			printf ("out buffer: %s", out_buf);
		i = send (sock_fh, out_buf + out_pos, out_len - out_pos, 0);
		if (i < 0)
			die ("!send");
		out_pos += i;
		if (out_pos > out_len)
			die ("wtf");
		if (out_pos == out_len)
			out_pos = out_len = 0;
	}
	if (pfd.revents & (POLLERR | POLLHUP)) {
		die ("pollerr or pollhup");
	}
}

static void
bench (int r) {
	int		i, j;

	for (j = 0; j < r; j++) {
		printf ("iteration %d\n", j);
		block.nonce[0] = j;
		block.nonce[1] = j >> 8;
		block.nonce[2] = j >> 16;
		block.nonce[3] = j >> 24;
		step0 (&block);
		for (i = 1; i <= WK; i++)
			step (i);
	}
	Log ("finished, %d total solutions", stat_found);
}

static void
usage (char **argv) {
	printf ("\nusage: %s\n", *argv);
	printf ("\t[-l pool_host]\t\t# default %s\n", pool_host);
	printf ("\t[-P pool_port]\t\t# default %d\n", pool_port);
	printf ("\t[-u worker_name]\t# default %s\n", worker_name);
	printf ("\t[-p worker_pass]\t# detault %s\n", worker_pass);
	printf ("\t[-d debug_level]\t# default %d\n", flag_debug);
	printf ("\t[-b benchmark_iters]\t# default %d\n", flag_bench);
	exit (0);
}

void
arg_parse (int argc, char **argv) {
	int		i;

	for (i = 1; i < argc; i++) {
		if (argv[i][0] != '-')
			die ("unknown argument, try -h");
		if (argv[i][1] == 'h') {
			usage (argv);
			exit (1);
		}
		if (i == argc - 1)
			die ("no value for parameter");
		switch (argv[i++][1]) {
		case 'l':
			strncpy (pool_host, argv[i], BUF_SIZE);
			break;
		case 'P':
			pool_port = atoi (argv[i]);
			break;
		case 'M':
			strncpy (miner_name, argv[i], BUF_SIZE);
			break;
		case 'u':
			strncpy (worker_name, argv[i], BUF_SIZE);
			break;
		case 'p':
			strncpy (worker_pass, argv[i], BUF_SIZE);
			break;
		case 'b':
			flag_bench = atoi (argv[i]);
			break;
		case 'd':
			flag_debug = atoi (argv[i]);
			break;
		default:
			die ("unknown option, try -h");
		}
	}
}

void
mine (void) {
	int			i;
	time_t			time_cur, t1, t2;

	time (&time_start);
	time_prev = time_last = time_start;
	for (;;) {
		periodic (0);
		if (flag_new_job) {
NEW_JOB:		flag_new_job = 0;
			memset (block.nonce + nonce1_len, 0,
			    sizeof (block.nonce) - nonce1_len);
		}
		if (flag_debug > 0) {
			for (i = (int)sizeof (block.nonce) - 1; !block.nonce[i]
			    && i > nonce1_len; i--)
				;
			printf ("nonce2 ");
			for (; i >= nonce1_len; i--)
				printf ("%02x", block.nonce[i]);
			printf ("\n");
		}

		time (&time_cur);
		if (time_cur - time_last > TIME_STAT_PERIOD) {
			t1 = time_cur - time_prev;
			if (!t1)
				t1 = 1;
			t2 = time_cur - time_start;
			if (!t2)
				t2 = 1;
			Log ("stat: cur %.2f Sol/s all %.2f Sol/s, total %d send %d "
			    "ok %d jobs %d interrupts %d\n",
			    (float)(stat_found_last + stat_found_cur) / t1,
			    (float)stat_found / t2,
			    stat_found, stat_submitted,
			    stat_accepted, stat_jobs, stat_interrupts);
			time_prev = time_last;
			time_last = time_cur;
			stat_found_last = stat_found_cur;
			stat_found_cur = 0;
		}

		step0 (&block);
		for (i = 1; i <= WK; i++) {
			periodic (0);
			if (flag_new_job) {
				stat_interrupts++;
				goto NEW_JOB;
			}
			step (i);
		}
		for (i = nonce1_len; i < (int)sizeof (block.nonce); i++)
			if (++block.nonce[i])
				break;
		if (i == (int)sizeof (block.nonce))
			die ("exhaused nonce");
	}
}

int
main (int argc, char **argv) {
	int		i;

	setvbuf (stdout, NULL, _IONBF, 0);

	Log ("Yet Another ZEC Miner, CPU miner for https://z.cash/");
	Log ("BLAKE2b implementation: %s", blake2b_info ());

	arg_parse (argc, argv);

	if (flag_bench) {
		bench (flag_bench);
		return 0;
	}

	Log ("connecting to %s:%d", pool_host, pool_port);
	if (sock_fh < 0)
		sock_open ();
	Log ("connected!\n");
	send_subscribe ();
	for (i = 0; !flag_new_job && i < 10; i++)
		periodic (1000);
	if (!flag_new_job)
		die ("no responses or jobs");

	mine ();
	return 0;
}
