/*
 * Copyright (C) Jakub Hrozek 2014 <jakub.hrozek@gmail.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#define ANSIZE 256

static void print_asc(const uint8_t *buf, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++) {
		printf("%c", isprint(buf[i])?buf[i]:'.');
	}
}

static void dump_data(const uint8_t *buf, int len)
{
	int i=0;
	static const uint8_t empty[16] = { 0, };

	if (len<=0) return;

	for (i=0; i<len;) {

		if (i%16 == 0) {
			if ((i > 0) &&
			    (len > i+16) &&
			    (memcmp(&buf[i], &empty, 16) == 0))
			{
				i +=16;
				continue;
			}

			if (i<len)  {
				printf("[%04X] ",i);
			}
		}

		printf("%02x ", buf[i]);
		i++;

		if (i%8 == 0) printf("  ");
		if (i%16 == 0) {
			print_asc(&buf[i-16],8); printf(" ");
			print_asc(&buf[i-8],8); printf("\n");
		}
	}

	if (i%16) {
		int n;
		n = 16 - (i%16);
		printf(" ");
		if (n>8) printf(" ");
		while (n--) printf("   ");
		n = MIN(8,i%16);
		print_asc(&buf[i-(i%16)],n); printf( " " );
		n = (i%16) - n;
		if (n>0) print_asc(&buf[i-n],n);
		printf("\n");
	}
}

static void test_res_query_a_record(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE] = { 0 };
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "cwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	printf("dump answer:\n");
	dump_data(answer, rv);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * fake hosts file contains
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "78.46.80.163");
}

static void test_res_query_srv_record(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE] = { 0 };
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */
	const uint8_t *rrdata;
	int prio;
	int weight;
	int port;
	char hostname[MAXDNAME];

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "_http._tcp.mxtoolbox.com", ns_c_in, ns_t_srv,
			answer, sizeof(answer));
	assert_in_range(rv, 1, 100);

	printf("dump answer:\n");
	dump_data(answer, rv);

	ns_initparse(answer, sizeof(answer), &handle);

	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type SRV and have the priority, weight,
	 * port and hostname as in the fake hosts file
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_srv);

	rrdata = ns_rr_rdata(rr);
	NS_GET16(prio, rrdata);
	NS_GET16(weight, rrdata);
	NS_GET16(port, rrdata);

	rv = ns_name_uncompress(ns_msg_base(handle),
				ns_msg_end(handle),
				rrdata,
				hostname, MAXDNAME);
	assert_int_not_equal(rv, -1);

	assert_int_equal(prio, 10);
	assert_int_equal(weight, 100);
	assert_int_equal(port, 80);
	assert_string_equal(hostname, "mxtoolbox.com");
}

int main(void)
{
	int rc;

	const UnitTest tests[] = {
		unit_test(test_res_query_a_record),
		unit_test(test_res_query_srv_record),
	};

	rc = run_tests(tests);

	return rc;
}
