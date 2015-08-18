/*
 * Copyright (C) Jakub Hrozek 2014 <jakub.hrozek@posteo.se>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *	notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *	notice, this list of conditions and the following disclaimer in the
 *	documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *	may be used to endorse or promote products derived from this software
 *	without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "config.h"

#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <getopt.h>

#ifndef PIDFILE
#define PIDFILE "dns_srv.pid"
#endif  /* PIDFILE */

#define DNS_PORT	53
#define DFL_TTL	 30

#ifndef BUFSIZE
#define BUFSIZE 1024
#endif /* BUFSIZE */

#ifndef discard_const
#define discard_const(ptr) ((void *)((uintptr_t)(ptr)))
#endif

#ifndef discard_const_p
#define discard_const_p(type, ptr) ((type *)discard_const(ptr))
#endif

#ifndef ZERO_STRUCT
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))
#endif

/* The macros below are taken from c-ares */
#define DNS__16BIT(p)  ((unsigned short)((unsigned int) 0xffff & \
			(((unsigned int)((unsigned char)(p)[0]) << 8U) | \
			((unsigned int)((unsigned char)(p)[1])))))

#define DNS__SET16BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 8) & 0xff)), \
			      ((p)[1] = (unsigned char)((v) & 0xff)))

#define DNS__SET32BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 24) & 0xff)), \
			      ((p)[1] = (unsigned char)(((v) >> 16) & 0xff)), \
			      ((p)[2] = (unsigned char)(((v) >> 8) & 0xff)), \
			      ((p)[3] = (unsigned char)((v) & 0xff)));

/* Macros for parsing a DNS header */
#define DNS_HEADER_QID(h)		DNS__16BIT(h)
#define DNS_HEADER_OPCODE(h)		(((h)[2] >> 3) & 0xf)
#define DNS_HEADER_TC(h)		(((h)[2] >> 1) & 0x1)
#define DNS_HEADER_QDCOUNT(h)		DNS__16BIT((h) + 4)

/* Macros for parsing the fixed part of a DNS question */
#define DNS_QUESTION_TYPE(q)		DNS__16BIT(q)
#define DNS_QUESTION_CLASS(q)		DNS__16BIT((q) + 2)

/* Macros for constructing a DNS header */
#define DNS_HEADER_SET_QID(h, v)	DNS__SET16BIT(h, v)
#define DNS_HEADER_SET_QR(h, v)		((h)[2] |= (unsigned char)(((v) & 0x1) << 7))
#define DNS_HEADER_SET_RD(h, v)		((h)[2] |= (unsigned char)((v) & 0x1))
#define DNS_HEADER_SET_RA(h, v)		((h)[3] |= (unsigned char)(((v) & 0x1) << 7))
#define DNS_HEADER_SET_QDCOUNT(h, v)	DNS__SET16BIT((h) + 4, v)
#define DNS_HEADER_SET_ANCOUNT(h, v)	DNS__SET16BIT((h) + 6, v)

/* Macros for constructing the fixed part of a DNS question */
#define DNS_QUESTION_SET_TYPE(q, v)	DNS__SET16BIT(q, v)
#define DNS_QUESTION_SET_CLASS(q, v)	DNS__SET16BIT((q) + 2, v)

/* Macros for constructing the fixed part of a DNS resource record */
#define DNS_RR_SET_TYPE(r, v)		DNS__SET16BIT(r, v)
#define DNS_RR_SET_CLASS(r, v)		DNS__SET16BIT((r) + 2, v)
#define DNS_RR_SET_TTL(r, v)		DNS__SET32BIT((r) + 4, v)
#define DNS_RR_SET_LEN(r, v)		DNS__SET16BIT((r) + 8, v)

#define DEFAULT_A_REC   "127.0.10.10"

struct dns_srv_opts {
	char *bind;
	bool daemon;
	int port;
	const char *pidfile;
};

struct dns_query {
	char *query;

	uint16_t id;
	uint16_t qtype;
	uint16_t qclass;

	unsigned char *reply;
	size_t reply_len;
};

static void free_dns_query(struct dns_query *query)
{
	free(query->query);
	free(query->reply);
	memset(query, 0, sizeof(struct dns_query));
}

static size_t encode_name(unsigned char *buffer, const char *name)
{
	const char *p, *dot;
	unsigned char *bp;
	size_t len;

	p = name;
	bp = buffer;
	len = 0;

	while ((dot = strchr(p, '.')) != NULL) {
		*bp++ = dot - p;
		len++;

		while (p < dot) {
			*bp++ = *p++;
			len++;
		}
		p = dot + 1; /* move past the dot */
	}

	*bp = '\0';
	len++;

	return len;
}

static void fake_header(struct dns_query *query)
{
	DNS_HEADER_SET_QID(query->reply, query->id);
	DNS_HEADER_SET_QR(query->reply, 1);
	DNS_HEADER_SET_RD(query->reply, 1);
	DNS_HEADER_SET_RA(query->reply, 1);
	DNS_HEADER_SET_QDCOUNT(query->reply, 1);
	DNS_HEADER_SET_ANCOUNT(query->reply, 1);
}

static size_t fake_question(struct dns_query *query, unsigned char **pout)
{
	unsigned char *p;
	size_t len;

	p = *pout;

	len = encode_name(p, query->query);
	p += len;
	DNS_QUESTION_SET_TYPE(p, query->qtype);
	len += sizeof(uint16_t);
	DNS_QUESTION_SET_CLASS(p, query->qclass);
	len += sizeof(uint16_t);

	p += 2 * sizeof(uint16_t);

	*pout = p;
	return len;
}

static size_t fake_answer(struct dns_query *query, unsigned char **pout)
{
	unsigned char *p;
	size_t len;
	size_t rlen;
	char *val;
	struct in_addr a_rec;

	p = *pout;

	len = encode_name(p, query->query);
	p += len;

	DNS_RR_SET_TYPE(p, query->qtype);
	len += sizeof(uint16_t);

	DNS_RR_SET_CLASS(p, query->qclass);
	len += sizeof(uint16_t);

	DNS_RR_SET_TTL(p, DFL_TTL);
	len += sizeof(uint32_t);

	switch (query->qtype) {
		case ns_t_a:
			val = getenv("RWRAP_TEST_A_REC");
			inet_pton(AF_INET,
				  val ? val : DEFAULT_A_REC,
				  &a_rec);
			rlen = sizeof(struct in_addr);
			break;
		default:
			/* Unhandled record */
			return -1;
	}

	DNS_RR_SET_LEN(p, rlen);
	len += sizeof(uint16_t);

	/* Move to the RDATA section */
	p += sizeof(uint16_t) +	/* type */
		 sizeof(uint16_t) +	/* class */
		 sizeof(uint32_t) +	/* ttl */
		 sizeof(uint16_t);	 /* rlen */

	/* Copy RDATA */
	memcpy(p, &a_rec, sizeof(struct in_addr));
	len += rlen;

	*pout = p;
	return len;
}

static int fake_reply(struct dns_query *query)
{
	unsigned char *p;

	query->reply = malloc(BUFSIZE);
	if (query->reply == NULL) {
		return ENOMEM;
	}

	memset(query->reply, 0, BUFSIZE);
	p = query->reply;

	fake_header(query);
	query->reply_len = NS_HFIXEDSZ;
	p += NS_HFIXEDSZ;

	/* advances p internally */
	query->reply_len += fake_question(query, &p);
	query->reply_len += fake_answer(query, &p);

	return 0;
}

static char *extract_name(char **buffer, size_t maxlen)
{
	char *query, *qp, *bp;
	unsigned int len;
	unsigned int i;

	query = malloc(maxlen);
	if (query == NULL) return NULL;

	i = 0;
	qp = query;
	bp = *buffer;
	do {
		len = *bp;
		bp++;

		if (len > (maxlen - (qp - query))) {
			/* label is past the buffer */
			free(query);
			return NULL;
		}

		for (i = 0; i < len; i++) {
			*qp++ = *bp++;
		}

		if (len > 0) {
			*qp++ = '.';
		} else {
			*qp = '\0';
		}
	} while (len > 0);

	*buffer = bp;
	return query;
}

static int parse_query(unsigned char *buffer,
		       size_t len,
		       struct dns_query *query)
{
	unsigned char *p;

	p = buffer;

	if (len < NS_HFIXEDSZ) {
		/* Message too short */
		return EBADMSG;
	}

	if (DNS_HEADER_OPCODE(p) != 0) {
		/* Queries must have the opcode set to 0 */
		return EBADMSG;
	}

	if (DNS_HEADER_QDCOUNT(p) != 1) {
		/* We only support one query */
		return EBADMSG;
	}

	if (len < NS_HFIXEDSZ + 2 * sizeof(uint16_t)) {
		/* No room for class and type */
		return EBADMSG;
	}

	/* Need to remember the query to respond with the same */
	query->id = DNS_HEADER_QID(p);

	/* Done with the header, move past it */
	p += NS_HFIXEDSZ;
	query->query = extract_name((char **) &p, len - NS_HFIXEDSZ);
	if (query->query == NULL) {
		return EIO;
	}

	query->qclass = DNS_QUESTION_CLASS(p);
	if (query->qclass != ns_c_in) {
		/* We only support Internet queries */
		return EBADMSG;
	}

	query->qtype = DNS_QUESTION_TYPE(p);
	return 0;
}

static void dns(int sock)
{
	struct sockaddr_storage css;
	socklen_t addrlen = sizeof(css);
	ssize_t bret;
	unsigned char buf[BUFSIZE];
	struct dns_query query;
	int rv;

	ZERO_STRUCT(query);

	while (1) {
		free_dns_query(&query);

		/* for advanced features, use recvmsg here */
		ZERO_STRUCT(buf);
		bret = recvfrom(sock, buf, BUFSIZE, 0,
				(struct sockaddr *) &css, &addrlen);
		if (bret == -1) {
			perror("recvfrom");
			continue;
		}

		/* parse query */
		rv = parse_query(buf, bret, &query);
		if (rv != 0) {
			continue;
		}

		/* Construct the reply */
		rv = fake_reply(&query);
		if (rv != 0) {
			continue;
		}

		/* send reply back */
		bret = sendto(sock, query.reply, query.reply_len, 0,
				(struct sockaddr *) &css, addrlen);
		if (bret == -1) {
			perror("sendto");
			continue;
		}
	}
}

static int pidfile(const char *path)
{
	int err;
	int fd;
	char pid_str[32] = { 0 };
	ssize_t nwritten;
	size_t len;

	fd = open(path, O_RDONLY, 0644);
	err = errno;
	if (fd != -1) {
		close(fd);
		return EEXIST;
	} else if (err != ENOENT) {
		return err;
	}

	fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
	err = errno;
	if (fd == -1) {
		return err;
	}

	snprintf(pid_str, sizeof(pid_str) -1, "%u\n", (unsigned int) getpid());
	len = strlen(pid_str);

	nwritten = write(fd, pid_str, len);
	close(fd);
	if (nwritten != (ssize_t)len) {
		return EIO;
	}

	return 0;
}

static int become_daemon(void)
{
	int ret;
	pid_t child_pid;
	int fd;
	int i;

	if (getppid() == 1) {
		return 0;
	}

	child_pid = fork();
	if (child_pid == -1) {
		ret = errno;
		perror("fork");
		return ret;
	} else if (child_pid > 0) {
		exit(0);
	}

	/* If a working directory was defined, go there */
#ifdef WORKING_DIR
	chdir(WORKING_DIR);
#endif

	ret = setsid();
	if (ret == -1) {
		ret = errno;
		perror("setsid");
		return ret;
	}

	for (fd = getdtablesize(); fd >= 0; --fd) {
		close(fd);
	}

	for (i = 0; i < 3; i++) {
		fd = open("/dev/null", O_RDWR, 0);
		if (fd < 0) {
			fd = open("/dev/null", O_WRONLY, 0);
		}
		if (fd < 0) {
			ret = errno;
			perror("Can't open /dev/null");
			return ret;
		}
		if (fd != i) {
			perror("Didn't get correct fd");
			close(fd);
			return EINVAL;
		}
	}

	umask(0177);
	return 0;
}

/*
 * Returns 0 on success, errno on failure.
 * If successful, sock is a ready to use socket.
 */
static int setup_srv(struct dns_srv_opts *opts, int *_sock)
{
	struct addrinfo hints;
	struct addrinfo *res, *ri;
	char svc[6];
	int ret;
	int sock;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(svc, sizeof(svc), "%d", opts->port);

	ret = getaddrinfo(opts->bind, svc, &hints, &res);
	if (ret != 0) {
		return errno;
	}

	for (ri = res; ri != NULL; ri = ri->ai_next) {
		sock = socket(ri->ai_family, ri->ai_socktype, ri->ai_protocol);
		if (sock == -1) {
			ret = errno;
			freeaddrinfo(res);
			perror("socket");
			return ret;
		}

		ret = bind(sock, ri->ai_addr, ri->ai_addrlen);
		if (ret == 0) {
			break;
		}

		close(sock);
	}
	freeaddrinfo(res);

	if (ri == NULL) {
		fprintf(stderr, "Could not bind\n");
		return EFAULT;
	}

	*_sock = sock;
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	int sock = -1;
	struct dns_srv_opts opts;
	int opt;
	int optindex;
	static struct option long_options[] = {
		{ discard_const_p(char, "bind-addr"),	required_argument,	0,  'b' },
		{ discard_const_p(char, "daemon"),	no_argument,		0,  'D' },
		{ discard_const_p(char, "port"),	required_argument,	0,  'p' },
		{ discard_const_p(char, "pid"),		required_argument,	0,  0 },
		{ 0,					0,			0,  0 }
	};

	opts.bind = NULL;
	opts.pidfile = PIDFILE;
	opts.daemon = false;
	opts.port = DNS_PORT;

	while ((opt = getopt_long(argc, argv, "Db:p:",
				  long_options, &optindex)) != -1)
	{
		switch (opt) {
		case 0:
			if (optindex == 3) {
				opts.pidfile = optarg;
			}
			break;
		case 'b':
			opts.bind = optarg;
			break;
		case 'D':
			opts.daemon = true;
			break;
		case 'p':
			opts.port = atoi(optarg);
			break;
		default: /* '?' */
			fprintf(stderr, "Usage: %s [-p port] [-b bind_addr] "
					"[-D] [--pid pidfile]\n"
					"-D tells the server to become a "
					"deamon and write a PIDfile\n"
					"The default PIDfile is '%s' "
					"in the current directory\n",
					PIDFILE, argv[0]);
			ret = 1;
			goto done;
		}
	}

	if (opts.daemon) {
		ret = become_daemon();
		if (ret != 0) {
			fprintf(stderr, "Cannot become daemon: %s\n",
				strerror(ret));
			goto done;
		}
	}

	ret = setup_srv(&opts, &sock);
	if (ret != 0) {
		fprintf(stderr, "Cannot setup server: %s\n", strerror(ret));
		goto done;
	}

	if (opts.daemon) {
		if (opts.pidfile == NULL) {
			fprintf(stderr, "Error: pidfile == NULL\n");
			ret = -1;
			goto done;
		}

		ret = pidfile(opts.pidfile);
		if (ret != 0) {
			fprintf(stderr, "Cannot create pidfile %s: %s\n",
				opts.pidfile, strerror(ret));
			goto done;
		}
	}

	dns(sock);
	close(sock);

	if (opts.daemon) {
		unlink(opts.pidfile);
	}

	ret = 0;

done:
	return ret;
}
