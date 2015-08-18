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
#include "torture.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>

#define ANSIZE 256

static int setup_dns_srv_ipv4(void **state)
{
	torture_setup_dns_srv_ipv4(state);
	setenv("RESOLV_WRAPPER_CONF", torture_server_resolv_conf(state), 1);

	return 0;
}

static int teardown(void **state)
{
	torture_teardown_dns_srv(state);

	return 0;
}

static void test_res_nquery(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nquery(&dnsstate, "www.cwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_int_not_equal(rv, -1);

	ns_initparse(answer, sizeof(answer), &handle);
	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * test server sends.
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.10.10");

	res_nclose(&dnsstate);
}

static void test_res_query(void **state)
{
	int rv;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	rv = res_query("www.cwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_int_not_equal(rv, -1);

	ns_initparse(answer, sizeof(answer), &handle);
	/*
	 * The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * test server sends.
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.10.10");
}

static void test_res_nsearch(void **state)
{
	int rv;
	struct __res_state dnsstate;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	memset(&dnsstate, 0, sizeof(struct __res_state));
	rv = res_ninit(&dnsstate);
	assert_int_equal(rv, 0);

	rv = res_nsearch(&dnsstate, "www.cwrap.org", ns_c_in, ns_t_a,
			 answer, sizeof(answer));
	assert_int_not_equal(rv, -1);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * test server sends
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.10.10");

	res_nclose(&dnsstate);
}

static void test_res_search(void **state)
{
	int rv;
	unsigned char answer[ANSIZE];
	char addr[INET_ADDRSTRLEN];
	ns_msg handle;
	ns_rr rr;   /* expanded resource record */

	(void) state; /* unused */

	rv = res_search("www.cwrap.org", ns_c_in, ns_t_a,
			answer, sizeof(answer));
	assert_int_not_equal(rv, -1);

	ns_initparse(answer, sizeof(answer), &handle);
	/* The query must finish w/o an error, have one answer and the answer
	 * must be a parseable RR of type A and have the address that our
	 * test server sends
	 */
	assert_int_equal(ns_msg_getflag(handle, ns_f_rcode), ns_r_noerror);
	assert_int_equal(ns_msg_count(handle, ns_s_an), 1);
	assert_int_equal(ns_parserr(&handle, ns_s_an, 0, &rr), 0);
	assert_int_equal(ns_rr_type(rr), ns_t_a);
	assert_non_null(inet_ntop(AF_INET, ns_rr_rdata(rr),
			addr, sizeof(addr)));
	assert_string_equal(addr, "127.0.10.10");
}

int main(void)
{
	int rc;

	const struct CMUnitTest res_tests[] = {
		cmocka_unit_test_setup_teardown(test_res_nquery,
						setup_dns_srv_ipv4,
						teardown),
		cmocka_unit_test_setup_teardown(test_res_query,
						setup_dns_srv_ipv4,
						teardown),
		cmocka_unit_test_setup_teardown(test_res_nsearch,
						setup_dns_srv_ipv4,
						teardown),
		cmocka_unit_test_setup_teardown(test_res_search,
						setup_dns_srv_ipv4,
						teardown),
	};

	rc = cmocka_run_group_tests(res_tests, NULL, NULL);

	return rc;
}
