/*
 * iwterator
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * See README and COPYING for more details.
 */

#include <unistd.h> // for optarg
#include <errno.h> // for ENOMEM, ...
#include <fcntl.h> // for O_RDONLY
#include <net/if.h> // for if_nametoindex

#include "iw.h"


/* libnl 1.x compatibility code */
#if !defined(CONFIG_LIBNL20) && !defined(CONFIG_LIBNL30)
static inline struct nl_handle *nl_socket_alloc(void)
{
	return nl_handle_alloc();
}

static inline void nl_socket_free(struct nl_sock *h)
{
	nl_handle_destroy(h);
}

static inline int nl_socket_set_buffer_size(struct nl_sock *sk,
					    int rxbuf, int txbuf)
{
	return nl_set_buffer_size(sk, rxbuf, txbuf);
}
#endif /* CONFIG_LIBNL20 && CONFIG_LIBNL30 */


static int nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

 out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static void nl80211_cleanup(struct nl80211_state *state)
{
	nl_socket_free(state->nl_sock);
}

static int cmd_size;

extern struct cmd __start___cmd;
extern struct cmd __stop___cmd;

#define for_each_cmd(_cmd)						\
	for (_cmd = &__start___cmd; _cmd < &__stop___cmd;		\
	     _cmd = (const struct cmd *)((char *)_cmd + cmd_size))

static void usage(void)
{
	printf("\nusage:\n"
	       "  iwterator [-i<ifname>]\n\n");
}

static int phy_lookup(char *name)
{
	char buf[200];
	int fd, pos;

	snprintf(buf, sizeof(buf), "/sys/class/ieee80211/%s/index", name);

	fd = open(buf, O_RDONLY);
	if (fd < 0)
		return -1;
	pos = read(fd, buf, sizeof(buf) - 1);
	if (pos < 0) {
		close(fd);
		return -1;
	}
	buf[pos] = '\0';
	close(fd);
	return atoi(buf);
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err,
		  void *arg)
{
	int *ret = arg;
	*ret = err->error;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_SKIP;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

static int run_cmd(struct nl80211_state *state, signed long long devidx,
		   enum id_input idby, enum command_identify_by command_idby,
		   const struct cmd *cmd)
{
	struct nl_msg *msg;
	struct nl_cb *cb;
	struct nl_cb *s_cb;
	int err;
	int iw_debug = 0; // TODO

	msg = nlmsg_alloc();
	if (!msg) {
		fprintf(stderr, "failed to allocate netlink message\n");
		return 2;
	}

	cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	s_cb = nl_cb_alloc(iw_debug ? NL_CB_DEBUG : NL_CB_DEFAULT);
	if (!cb || !s_cb) {
		fprintf(stderr, "failed to allocate netlink callbacks\n");
		err = 2;
		goto out_free_msg;
	}

	genlmsg_put(msg, 0, 0, state->nl80211_id, 0,
		    cmd->nl_msg_flags, cmd->cmd, 0);

	switch (command_idby) {
	case CIB_PHY:
		NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devidx);
		break;
	case CIB_NETDEV:
		NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, devidx);
		break;
	case CIB_WDEV:
		NLA_PUT_U64(msg, NL80211_ATTR_WDEV, devidx);
		break;
	default:
		break;
	}

	err = cmd->handler(state, cb, msg, 0, NULL, idby);
	if (err)
		goto out;

	nl_socket_set_cb(state->nl_sock, s_cb);

	err = nl_send_auto_complete(state->nl_sock, msg);
	if (err < 0)
		goto out;

	err = 1;

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	while (err > 0)
		nl_recvmsgs(state->nl_sock, cb);
 out:
	nl_cb_put(cb);
 out_free_msg:
	nlmsg_free(msg);
	return err;
 nla_put_failure:
	fprintf(stderr, "building message failed\n");
	return 2;
}

static int iterate_cmd(struct nl80211_state *state, signed long long devidx,
		       enum id_input idby, enum command_identify_by command_idby)
{
	int ret;
	const struct cmd *cmd;

	for_each_cmd(cmd) {
		if (!cmd->parent ||
		    !cmd->parent->name)
			continue;

		fprintf(stderr, "\ncommand: name=%s, parent=%s\n", cmd->name, cmd->parent->name);

		//filter out the commands we want to be executed
		if ((strcmp(cmd->name, "power_save") ||
		     strcmp(cmd->parent->name, "get")) &&
		    (strcmp(cmd->name, "dump") ||
		     strcmp(cmd->parent->name, "station")) &&
		     (strcmp(cmd->name, "dump") ||
		     strcmp(cmd->parent->name, "scan")))
			continue;

		ret = run_cmd(state, devidx, idby, command_idby, cmd);
		if (ret)
			return ret;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct nl80211_state nlstate;
	int err;
	signed long long devidx = 0;
	enum id_input idby = II_NETDEV;
	enum command_identify_by command_idby = CIB_NONE;
	char *tmp, *ifname = "";

	/* calculate command size including padding */
	cmd_size = abs((long)&__section_set - (long)&__section_get);

	if (argc == 1) {
		usage();
		return 0;
	}

	for (;;) {
		int c = getopt(argc, argv, "i:");
		if (c < 0)
			break;
		switch (c) {
		case 'i':
			ifname = optarg;
			break;
		default:
			usage();
			return 0;
		}
	}

	// TODO currently II_NETDEV is hardcoded
	switch (idby) {
	case II_PHY_IDX:
		command_idby = CIB_PHY;
		devidx = strtoul(ifname + 4, &tmp, 0);
		if (*tmp != '\0')
			return 1;
		break;
	case II_PHY_NAME:
		command_idby = CIB_PHY;
		devidx = phy_lookup(ifname);
		break;
	case II_NETDEV:
		command_idby = CIB_NETDEV;
		devidx = if_nametoindex(ifname);
		if (devidx == 0)
			return 1;
		break;
	case II_WDEV:
		command_idby = CIB_WDEV;
		devidx = strtoll(ifname, &tmp, 0);
		if (*tmp != '\0')
			return 1;
		break;
	default:
		break;
	}

	err = nl80211_init(&nlstate);
	if (err)
		return 1;

	err = iterate_cmd(&nlstate, devidx, idby, command_idby);
	if (err == 1)
		usage();
	else if (err < 0)
		fprintf(stderr, "command failed: %s (%d)\n", strerror(-err), err);

	nl80211_cleanup(&nlstate);

	return err;
}
