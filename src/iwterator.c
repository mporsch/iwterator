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

int iw_debug = 0;

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
	       "  iwterator [<ifnames/phynames>]\n\n");
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

static int filter_cmd(const struct cmd *cmd,
		      enum command_identify_by command_idby)
{
	int i;
	static const char * const cmd_names[] = {
		"dump",
		"dump",
		"power_save",
	};
	static const enum nl80211_commands cmd_cmds[] = {
			NL80211_CMD_GET_STATION,
			NL80211_CMD_GET_SCAN,
			NL80211_CMD_GET_POWER_SAVE,
	};

	/* not for this device type */
	if (cmd->idby != command_idby)
		return 1;

	/* check the combination name - nl80211_command */
	for (i = 0; i < ARRAY_SIZE(cmd_names); i++) {
		if (strcmp(cmd_names[i], cmd->name) == 0 &&
		    cmd_cmds[i] == cmd->cmd)
			return 0;
	}

	return 1;
}

static int iterate_cmd(struct nl80211_state *state, signed long long devidx,
		       enum id_input idby, enum command_identify_by command_idby,
		       char *ifname)
{
	int err = 0;
	const struct cmd *cmd;

	for_each_cmd(cmd) {
		if (filter_cmd(cmd, command_idby))
			continue;

		fprintf(stderr, "\n%s %s %s\n", ifname, cmd->parent ? cmd->parent->name : "", cmd->name);

		err = run_cmd(state, devidx, idby, command_idby, cmd);
		if (err)
			break;
	}

	return err;
}

static int iterate_dev(struct nl80211_state *state,
		       int argc, char *argv[])
{
	int i, idx, err = 0;
	signed long long devidx = 0;
	enum id_input idby = II_NONE;
	enum command_identify_by command_idby = CIB_NONE;
	char *tmp;

	for (i = 0; i < argc; i++) {
		/* detect interface or phy name */
		if ((idx = if_nametoindex(argv[i])) != 0)
			idby = II_NETDEV;
		else if ((idx = phy_lookup(argv[i])) >= 0)
			idby = II_PHY_NAME;
		else
			return 1;

		switch (idby) {
		case II_PHY_IDX:
			command_idby = CIB_PHY;
			devidx = strtoul(argv[i] + 4, &tmp, 0);
			if (*tmp != '\0')
				return 1;
			break;
		case II_PHY_NAME:
			command_idby = CIB_PHY;
			devidx = phy_lookup(argv[i]);
			break;
		case II_NETDEV:
			command_idby = CIB_NETDEV;
			devidx = if_nametoindex(argv[i]);
			if (devidx == 0)
				return 1;
			break;
		case II_WDEV:
			command_idby = CIB_WDEV;
			devidx = strtoll(argv[i], &tmp, 0);
			if (*tmp != '\0')
				return 1;
			break;
		default:
			return 1;
		}

		err = iterate_cmd(state, devidx, idby, command_idby, argv[i]);
		if (err)
			break;
	}

	return err;
}

int main(int argc, char *argv[])
{
	struct nl80211_state nlstate;
	int err;

	/* calculate command size including padding */
	cmd_size = abs((long)&__section_set - (long)&__section_get);

	/* strip off self */
	argc--;
	argv++;
	/* params given? */
	if (argc == 0) {
		usage();
		return 0;
	}
	if (strcmp(*argv, "--debug") == 0) {
		iw_debug = 1;
		argc--;
		argv++;
	}

	err = nl80211_init(&nlstate);
	if (err)
		return 1;

	err = iterate_dev(&nlstate, argc, argv);
	if (err == 1)
		usage();
	else if (err < 0)
		fprintf(stderr, "command failed: %s (%d)\n", strerror(-err), err);

	nl80211_cleanup(&nlstate);

	return err;
}
