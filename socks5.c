/* $Id$ */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "utils.h"
#include "log.h"
#include "redsocks.h"

typedef enum socks5_state_t {
	socks5_new,
	socks5_method_sent,
	socks5_auth_sent,
	socks5_request_sent,
	socks5_skip_domain,
	socks5_skip_address,
	socks5_MAX,
} socks5_state;

typedef struct socks5_client_t {
	int do_password; // 1 - password authentication is possible
	int to_skip;     // valid while reading last reply (after main request)
} socks5_client;

typedef struct socks5_method_req_t {
	uint8_t ver;
	uint8_t num_methods;
	uint8_t methods[1]; // at least one
} PACKED socks5_method_req;

typedef struct socks5_method_reply_t {
	uint8_t ver;
	uint8_t method;
} PACKED socks5_method_reply;

const int socks5_ver = 5;

const int socks5_auth_none = 0x00;
const int socks5_auth_gssapi = 0x01;
const int socks5_auth_password = 0x02;
const int socks5_auth_invalid = 0xFF;

typedef struct socks5_auth_reply_t {
	uint8_t ver;
	uint8_t status;
} PACKED socks5_auth_reply;

const int socks5_password_ver = 0x01;
const int socks5_password_passed = 0x00;


typedef struct socks5_addr_ipv4_t {
	uint32_t addr;
	uint16_t port;
} PACKED socks5_addr_ipv4;

typedef struct socks5_addr_domain_t {
	uint8_t size;
	uint8_t more[1];
	/* uint16_t port; */
} PACKED socks5_addr_domain;

typedef struct socks5_addr_ipv6_t {
	uint8_t addr[16];
	uint16_t port;
} PACKED socks5_addr_ipv6;

typedef struct socks5_req_t {
	uint8_t ver;
	uint8_t cmd;
	uint8_t reserved;
	uint8_t addrtype;
	/* socks5_addr_* */
} PACKED socks5_req;

typedef struct socks5_reply_t {
	uint8_t ver;
	uint8_t status;
	uint8_t reserved;
	uint8_t addrtype;
	/* socks5_addr_* */
} PACKED socks5_reply;

const int socks5_reply_maxlen = 512; // as domain name can't be longer than 256 bytes
const int socks5_cmd_connect = 1;
const int socks5_cmd_bind = 2;
const int socks5_cmd_udp_associate = 2;
const int socks5_addrtype_ipv4 = 1;
const int socks5_addrtype_domain = 3;
const int socks5_addrtype_ipv6 = 4;
const int socks5_status_succeeded = 0;
const int socks5_status_server_failure = 1;
const int socks5_status_connection_not_allowed_by_ruleset = 2;
const int socks5_status_Network_unreachable = 3;
const int socks5_status_Host_unreachable = 4;
const int socks5_status_Connection_refused = 5;
const int socks5_status_TTL_expired = 6;
const int socks5_status_Command_not_supported = 7;
const int socks5_status_Address_type_not_supported = 8;

const char *socks5_strstatus[] = {
	"ok", 
	"server failure",
	"connection not allowed by ruleset",
	"network unreachable",
	"host unreachable",
	"connection refused",
	"TTL expired",
	"command not supported",
	"address type not supported",
};

void socks5_client_init(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	const redsocks_config *config = &client->instance->config;

	client->state = socks5_new;
	socks5->do_password = 0;
	if (config->login && config->password) {
		if (strlen(config->login) > 255)
			redsocks_log_error(client, LOG_WARNING, "Socks5 login can't be more than 255 chars");
		else if (strlen(config->password) > 255)
			redsocks_log_error(client, LOG_WARNING, "Socks5 password can't be more than 255 chars");
		else
			socks5->do_password = 1;
	}
}

static struct evbuffer *socks5_mkmethods(redsocks_client *client)
{
	socks5_client *socks5 = (void*)(client + 1);
	int len = sizeof(socks5_method_req) + socks5->do_password;
	union {
		socks5_method_req req;
		uint8_t raw[len];
	} u;

	u.req.ver = socks5_ver;
	u.req.num_methods = 1 + socks5->do_password;
	u.req.methods[0] = socks5_auth_none;
	if (socks5->do_password)
		u.req.methods[1] = socks5_auth_password;

	return mkevbuffer(&u.req, len);
}

static struct evbuffer *socks5_mkpassword(redsocks_client *client)
{
	const char *login = client->instance->config.login;
	const char *password = client->instance->config.password;
	size_t ulen = strlen(login);
	size_t plen = strlen(password);
	size_t length =  1 /* version */ + 1 + ulen + 1 + plen;
	uint8_t req[length];
	
	req[0] = socks5_password_ver; // RFC 1929 says so
	req[1] = ulen;
	memcpy(&req[2], login, ulen);
	req[2+ulen] = plen;
	memcpy(&req[3+ulen], password, plen);
	return mkevbuffer(req, length);
}

static struct evbuffer *socks5_mkconnect(redsocks_client *client)
{
	struct {
		socks5_req head;
		socks5_addr_ipv4 ip;
	} PACKED req;

	req.head.ver = socks5_ver;
	req.head.cmd = socks5_cmd_connect;
	req.head.reserved = 0;
	req.head.addrtype = socks5_addrtype_ipv4;
	req.ip.addr = client->destaddr.sin_addr.s_addr;
	req.ip.port = client->destaddr.sin_port;
	return mkevbuffer(&req, sizeof(req));
}

static void socks5_write_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;

	if (client->state == socks5_new) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkmethods, socks5_method_sent, sizeof(socks5_method_reply)
			);
	}
}

static void socks5_read_auth_methods(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_method_reply reply;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_equal, sizeof(reply)) < 0)
		return;
		
	if (reply.ver != socks5_ver) {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected auth methods reply version...");
		redsocks_drop_client(client);
	}
	else if (reply.method == socks5_auth_none) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkconnect, socks5_request_sent, sizeof(socks5_reply)
			);
	}
	else if (reply.method == socks5_auth_password && socks5->do_password) {
		redsocks_write_helper(
			buffev, client,
			socks5_mkpassword, socks5_auth_sent, sizeof(socks5_auth_reply)
			);
	}
	else {
		if (reply.method != socks5_auth_invalid)
			redsocks_log_error(client, LOG_NOTICE, "Socks5 server requested unexpected auth method...");
		redsocks_drop_client(client);
	}
}

static void socks5_read_auth_reply(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_auth_reply reply;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_equal, sizeof(reply)) < 0)
		return;

	if (reply.ver != socks5_password_ver) {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected auth reply version...");
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_password_passed)
		redsocks_write_helper(
			buffev, client,
			socks5_mkconnect, socks5_request_sent, sizeof(socks5_reply)
			);
	else
		redsocks_drop_client(client);
}

static void socks5_read_reply(struct bufferevent *buffev, redsocks_client *client, socks5_client *socks5)
{
	socks5_reply reply;

	if (redsocks_read_expected(client, buffev->input, &reply, sizes_greater_equal, sizeof(reply)) < 0)
		return;

	if (reply.ver != socks5_ver) {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server reported unexpected reply version...");
		redsocks_drop_client(client);
	}
	else if (reply.status == socks5_status_succeeded) {
		socks5_state nextstate;
		size_t len;

		if (reply.addrtype == socks5_addrtype_ipv4) {
			len = socks5->to_skip = sizeof(socks5_addr_ipv4);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_ipv6) {
			len = socks5->to_skip = sizeof(socks5_addr_ipv6);
			nextstate = socks5_skip_address;
		}
		else if (reply.addrtype == socks5_addrtype_domain) {
			socks5_addr_domain domain;
			len = sizeof(domain.size);
			nextstate = socks5_skip_domain;
		}

		redsocks_write_helper(
			buffev, client,
			NULL, nextstate, len
			);
	}
	else {
		redsocks_log_error(client, LOG_NOTICE, "Socks5 server status: %s (%i)",
				/* 0 <= reply.status && */ reply.status < SIZEOF_ARRAY(socks5_strstatus)
				? socks5_strstatus[reply.status] : "?", reply.status);
		redsocks_drop_client(client);
	}
}

static void socks5_read_cb(struct bufferevent *buffev, void *_arg)
{
	redsocks_client *client = _arg;
	socks5_client *socks5 = (void*)(client + 1);

	if (client->state == socks5_method_sent) {
		socks5_read_auth_methods(buffev, client, socks5);
	}
	else if (client->state == socks5_auth_sent) {
		socks5_read_auth_reply(buffev, client, socks5);
	}
	else if (client->state == socks5_request_sent) {
		socks5_read_reply(buffev, client, socks5);
	}
	else if (client->state == socks5_skip_domain) {
		socks5_addr_ipv4 ipv4; // all socks5_addr*.port are equal
		uint8_t size;
		if (redsocks_read_expected(client, buffev->input, &size, sizes_greater_equal, sizeof(size)) < 0)
			return;
		socks5->to_skip = size + sizeof(ipv4.port);
		redsocks_write_helper(
			buffev, client,
			NULL, socks5_skip_address, socks5->to_skip
			);
	}
	else if (client->state == socks5_skip_address) {
		uint8_t data[socks5->to_skip];
		if (redsocks_read_expected(client, buffev->input, data, sizes_greater_equal, socks5->to_skip) < 0)
			return;
		redsocks_start_relay(client);
	}
	else {
		redsocks_drop_client(client);
	}
}

relay_subsys socks5_subsys = 
{
	.name        = "socks5",
	.payload_len = sizeof(socks5_client),
	.readcb      = socks5_read_cb,
	.writecb     = socks5_write_cb,
	.init        = socks5_client_init,
};


/* vim:set tabstop=4 softtabstop=4 shiftwidth=4: */
/* vim:set foldmethod=marker foldlevel=32 foldmarker={,}: */
