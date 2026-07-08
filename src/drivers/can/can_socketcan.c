

#include <csp/drivers/can_socketcan.h>

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <csp/csp_debug.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/can/raw.h>
#include <libsocketcan.h>

#include <csp/csp.h>

// CAN interface data, state, etc.
typedef struct {
	char name[CSP_IFLIST_NAME_MAX + 1];
	csp_iface_t iface;
	csp_can_interface_data_t ifdata;
	pthread_t rx_thread;
	int socket;
	int use_canfd;
} can_context_t;

static unsigned int socketcan_tx_frame_delay_usec(void) {
	static int initialized = 0;
	static unsigned int delay_usec = 0;

	if (!initialized) {
		const char * value = getenv("COMM_CSP_SOCKETCAN_TX_FRAME_DELAY_USEC");
		if (value != NULL && value[0] != '\0') {
			char * end = NULL;
			errno = 0;
			unsigned long parsed = strtoul(value, &end, 10);
			if ((errno == 0) && (end != value) && (*end == '\0')) {
				delay_usec = (unsigned int)parsed;
			}
		}
		initialized = 1;
	}

	return delay_usec;
}

static int socketcan_use_canfd(void) {
	static int initialized = 0;
	static int enabled = 0;

	if (!initialized) {
		const char * value = getenv("COMM_CSP_SOCKETCAN_USE_CANFD");
		enabled = (value != NULL) && (value[0] != '\0') && (strcmp(value, "0") != 0);
		initialized = 1;
	}

	return enabled;
}

static void socketcan_parse_canfd_dest_allowlist(csp_can_interface_data_t * ifdata) {
	if (ifdata == NULL) {
		return;
	}

	ifdata->canfd_dest_allowlist_count = 0;

	const char * value = getenv("COMM_CSP_SOCKETCAN_CANFD_DEST_ALLOWLIST");
	if ((value == NULL) || (value[0] == '\0')) {
		return;
	}

	char * copy = strdup(value);
	if (copy == NULL) {
		return;
	}

	char * saveptr = NULL;
	for (char * token = strtok_r(copy, ",", &saveptr);
		 token != NULL;
		 token = strtok_r(NULL, ",", &saveptr)) {
		while (*token == ' ' || *token == '\t') {
			token++;
		}
		if (*token == '\0') {
			continue;
		}

		char * end = NULL;
		errno = 0;
		unsigned long parsed = strtoul(token, &end, 10);
		while (end != NULL && (*end == ' ' || *end == '\t')) {
			end++;
		}
		if ((errno != 0) || (end == token) || (end == NULL) || (*end != '\0') || (parsed > CFP2_DST_MASK)) {
			continue;
		}

		if (ifdata->canfd_dest_allowlist_count >= CSP_CAN_MAX_CANFD_DEST_ALLOWLIST) {
			break;
		}

		ifdata->canfd_dest_allowlist[ifdata->canfd_dest_allowlist_count++] = (uint16_t) parsed;
	}

	free(copy);
}

static void socketcan_parse_canfd_dport_allowlist(csp_can_interface_data_t * ifdata) {
	if (ifdata == NULL) {
		return;
	}

	ifdata->canfd_dport_allowlist_count = 0;

	const char * value = getenv("COMM_CSP_SOCKETCAN_CANFD_DPORT_ALLOWLIST");
	if ((value == NULL) || (value[0] == '\0')) {
		return;
	}

	char * copy = strdup(value);
	if (copy == NULL) {
		return;
	}

	char * saveptr = NULL;
	for (char * token = strtok_r(copy, ",", &saveptr);
		 token != NULL;
		 token = strtok_r(NULL, ",", &saveptr)) {
		while (*token == ' ' || *token == '\t') {
			token++;
		}
		if (*token == '\0') {
			continue;
		}

		char * end = NULL;
		errno = 0;
		unsigned long parsed = strtoul(token, &end, 10);
		while (end != NULL && (*end == ' ' || *end == '\t')) {
			end++;
		}
		if ((errno != 0) || (end == token) || (end == NULL) || (*end != '\0') || (parsed > CFP2_DPORT_MASK)) {
			continue;
		}

		if (ifdata->canfd_dport_allowlist_count >= CSP_CAN_MAX_CANFD_DPORT_ALLOWLIST) {
			break;
		}

		ifdata->canfd_dport_allowlist[ifdata->canfd_dport_allowlist_count++] = (uint8_t) parsed;
	}

	free(copy);
}

static void socketcan_free(can_context_t * ctx) {

	if (ctx) {
		if (ctx->socket >= 0) {
			close(ctx->socket);
		}
		free(ctx);
	}
}

static void * socketcan_rx_thread(void * arg) {
	can_context_t * ctx = arg;

	while (1) {

		/* Use select for non blocking reads */
		fd_set input;
		FD_ZERO(&input);
		FD_SET(ctx->socket, &input);
		struct timeval timeout = {
			.tv_sec = 10,
		};
		int n = select(ctx->socket + 1, &input, NULL, NULL, &timeout);
		if (n == -1) {
			csp_print("CAN read error\n");
			continue;
		} else if (n == 0) {
			//printf("CAN idle\n");
			continue;
		}

		if (ctx->use_canfd) {
			struct canfd_frame frame;
			int nbytes = read(ctx->socket, &frame, sizeof(frame));
			if (nbytes < 0) {
				if (errno == EAGAIN || errno == EINTR) {
					continue;
				} else {
					csp_print("%s[%s]: read() failed, errno %d: %s\n", __func__, ctx->name, errno, strerror(errno));
					usleep(1*1E6);
					continue;
				}
			}

			if ((nbytes != CANFD_MTU) && (nbytes != CAN_MTU)) {
				csp_print("%s[%s]: Read incomplete CAN/CAN FD frame, size: %d, expected: %u or %u bytes\n",
						  __func__,
						  ctx->name,
						  nbytes,
						  (unsigned int)CAN_MTU,
						  (unsigned int)CANFD_MTU);
				continue;
			}

			if ((nbytes == CAN_MTU) && (frame.len > CAN_MAX_DLEN)) {
				continue;
			}

			if ((nbytes == CANFD_MTU) && (frame.len > CANFD_MAX_DLEN)) {
				continue;
			}

			if (!(frame.can_id & CAN_EFF_FLAG)) {
				continue;
			}

			if (frame.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
				csp_print("%s[%s]: discarding ERR/RTR/SFF CAN FD frame\n", __func__, ctx->name);
				continue;
			}

			frame.can_id &= CAN_EFF_MASK;
			csp_can_rx(&ctx->iface, frame.can_id, frame.data, frame.len, NULL);
			continue;
		}

		/* Read CAN frame */
		struct can_frame frame;
		int nbytes = read(ctx->socket, &frame, sizeof(frame));
		if (nbytes < 0) {
			if (errno == EAGAIN || errno == EINTR) {
				/* This is acceptable, since something interrupted us, try again */
				continue;
			} else {
				csp_print("%s[%s]: read() failed, errno %d: %s\n", __func__, ctx->name, errno, strerror(errno));
				usleep(1*1E6);
				continue;
			}
		}

		if (nbytes != sizeof(frame)) {
			csp_print("%s[%s]: Read incomplete CAN frame, size: %d, expected: %u bytes\n", __func__, ctx->name, nbytes, (unsigned int)sizeof(frame));
			continue;
		}

		/* Drop frames with invalid size field */
		if (frame.can_dlc > CAN_MAX_DLEN) {
			continue;
		}

		/* Drop frames with standard id (CSP uses extended) */
		if (!(frame.can_id & CAN_EFF_FLAG)) {
			continue;
		}

		/* Drop error and remote frames */
		if (frame.can_id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
			csp_print("%s[%s]: discarding ERR/RTR/SFF frame\n", __func__, ctx->name);
			continue;
		}

		/* Strip flags */
		frame.can_id &= CAN_EFF_MASK;

		/* Call RX callbacsp_can_rx_frameck */
		csp_can_rx(&ctx->iface, frame.can_id, frame.data, frame.can_dlc, NULL);
	}

	/* We should never reach this point */
	pthread_exit(NULL);
}

static int csp_can_tx_frame(void * driver_data, uint32_t id, const uint8_t * data, uint8_t dlc) {
	uint32_t waiting_ms = 0;
	const unsigned int interframe_delay_usec = socketcan_tx_frame_delay_usec();
	can_context_t * ctx = driver_data;
	uintptr_t pdata = 0;
	uintptr_t pend = 0;
	size_t length = 0;

	struct can_frame frame;
	struct canfd_frame frame_fd;
	const uint16_t dest = csp_can_get_dest_from_id(id);
	const int use_canfd = csp_can_dest_uses_canfd(&ctx->iface, dest);
	if (use_canfd) {
		if (dlc > CANFD_MAX_DLEN) {
			return CSP_ERR_INVAL;
		}
		memset(&frame_fd, 0, sizeof(frame_fd));
		frame_fd.can_id = id | CAN_EFF_FLAG;
		frame_fd.len = dlc;
		memcpy(frame_fd.data, data, dlc);
		pdata = (uintptr_t)&frame_fd;
		pend = ((uintptr_t)&frame_fd + sizeof(frame_fd));
		length = sizeof(frame_fd);
	} else {
		if (dlc > CAN_MAX_DLEN) {
			return CSP_ERR_INVAL;
		}
		memset(&frame, 0, sizeof(frame));
		frame.can_id = id | CAN_EFF_FLAG;
		frame.can_dlc = dlc;
		memcpy(frame.data, data, dlc);
		pdata = (uintptr_t)&frame;
		pend = ((uintptr_t)&frame + sizeof(frame));
		length = sizeof(frame);
	}

	while (pdata < pend) {
		int written;

		written = write(ctx->socket, (void *)pdata, length);
		if (written < 0) {
			if (errno == ENOBUFS) {
				/* If no space available, wait for 5 ms and try again */
				usleep(5000);
				waiting_ms += 5;
			} else if(errno == EAGAIN || errno == EINTR) {
				/* Acceptable, since something interrupted us, try again */
				waiting_ms += 5;
			} else {
				csp_print("%s[%s]: write() failed, encountered an error during write(). %d - '%s'\n", __func__, ctx->name, errno, strerror(errno));
				return CSP_ERR_TX;
			}

			if (waiting_ms >= 1000) {
				/* We finally got tired of waiting, give up */
				csp_print("%s[%s]: write() failed, we have been waiting for CAN buffers for too long (>1000 ms)\n", __func__, ctx->name);
				return CSP_ERR_TX;
			}
		} else {
			waiting_ms = 0;
			pdata += written;
			length -= written;
			if ((interframe_delay_usec > 0) && (pdata < pend)) {
				usleep(interframe_delay_usec);
			}
		}
	}

	return CSP_ERR_NONE;
}

static int csp_can_socketcan_set_promisc(const bool promisc, can_context_t * ctx) {
	struct can_filter filter = {
		.can_id = CFP_MAKE_DST(ctx->iface.addr),
		.can_mask = 0x0000, /* receive anything */
	};

	if (ctx->socket == 0) {
		return CSP_ERR_INVAL;
	}

	if (!promisc) {
		if (csp_conf.version == 1) {
			filter.can_id = CFP_MAKE_DST(ctx->iface.addr);
			filter.can_mask = CFP_MAKE_DST((1 << CFP_HOST_SIZE) - 1);
		} else {
			filter.can_id = ctx->iface.addr << CFP2_DST_OFFSET;
			filter.can_mask = CFP2_DST_MASK << CFP2_DST_OFFSET;
		}
	}

	if (setsockopt(ctx->socket, SOL_CAN_RAW, CAN_RAW_FILTER, &filter, sizeof(filter)) < 0) {
		csp_print("%s: setsockopt() failed, error: %s\n", __func__, strerror(errno));
		return CSP_ERR_INVAL;
	}

	return CSP_ERR_NONE;
}


int csp_can_socketcan_open_and_add_interface(const char * device, const char * ifname, unsigned int node_id, int bitrate, bool promisc, csp_iface_t ** return_iface) {
	if (ifname == NULL) {
		ifname = CSP_IF_CAN_DEFAULT_NAME;
	}

	csp_print("INIT %s: device: [%s], bitrate: %d, promisc: %d\n", ifname, device, bitrate, promisc);

	/* Set interface up - this may require increased OS privileges */
	if (bitrate > 0) {
		can_do_stop(device);
		can_set_bitrate(device, bitrate);
		can_set_restart_ms(device, 100);
		can_do_start(device);
	}

	can_context_t * ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return CSP_ERR_NOMEM;
	}
	ctx->socket = -1;

	strncpy(ctx->name, ifname, sizeof(ctx->name) - 1);
	ctx->iface.name = ctx->name;
	ctx->iface.addr = node_id;
	ctx->iface.interface_data = &ctx->ifdata;
	ctx->iface.driver_data = ctx;
	ctx->ifdata.tx_func = csp_can_tx_frame;
	ctx->ifdata.pbufs = NULL;
	ctx->use_canfd = socketcan_use_canfd();
	ctx->ifdata.classic_frame_dlen = CAN_MAX_DLEN;
	ctx->ifdata.frame_dlen = ctx->use_canfd ? CANFD_MAX_DLEN : CAN_MAX_DLEN;
	socketcan_parse_canfd_dest_allowlist(&ctx->ifdata);
	socketcan_parse_canfd_dport_allowlist(&ctx->ifdata);

	/* Create socket */
	if ((ctx->socket = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
		csp_print("%s[%s]: socket() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		socketcan_free(ctx);
		return CSP_ERR_INVAL;
	}

	/* Locate interface */
	struct ifreq ifr;
	strncpy(ifr.ifr_name, device, IFNAMSIZ - 1);
	if (ioctl(ctx->socket, SIOCGIFINDEX, &ifr) < 0) {
		csp_print("%s[%s]: device: [%s], ioctl() failed, error: %s\n", __func__, ctx->name, device, strerror(errno));
		socketcan_free(ctx);
		return CSP_ERR_INVAL;
	}

	fcntl(ctx->socket, F_SETFL, O_NONBLOCK);

	if (ctx->use_canfd) {
		const int enable_canfd = 1;
		if (setsockopt(ctx->socket, SOL_CAN_RAW, CAN_RAW_FD_FRAMES, &enable_canfd, sizeof(enable_canfd)) < 0) {
			csp_print("%s[%s]: setsockopt(CAN_RAW_FD_FRAMES) failed, error: %s\n", __func__, ctx->name, strerror(errno));
			socketcan_free(ctx);
			return CSP_ERR_INVAL;
		}
	}

	struct sockaddr_can addr;
	memset(&addr, 0, sizeof(addr));
	/* Bind the socket to CAN interface */
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;
	if (bind(ctx->socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		csp_print("%s[%s]: bind() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		socketcan_free(ctx);
		return CSP_ERR_INVAL;
	}

	/* Set filter mode */
	if (csp_can_socketcan_set_promisc(promisc, ctx) != CSP_ERR_NONE) {
		csp_print("%s[%s]: csp_can_socketcan_set_promisc() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		socketcan_free(ctx);
		return CSP_ERR_INVAL;
	}

	/* Add interface to CSP */
	int res = csp_can_add_interface(&ctx->iface);
	if (res != CSP_ERR_NONE) {
		csp_print("%s[%s]: csp_can_add_interface() failed, error: %d\n", __func__, ctx->name, res);
		socketcan_free(ctx);
		return res;
	}

	/* Create receive thread */
	if (pthread_create(&ctx->rx_thread, NULL, socketcan_rx_thread, ctx) != 0) {
		csp_print("%s[%s]: pthread_create() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		(void)csp_can_remove_interface(&ctx->iface);
		socketcan_free(ctx);
		return CSP_ERR_NOMEM;
	}

	if (return_iface) {
		*return_iface = &ctx->iface;
	}

	return CSP_ERR_NONE;
}

csp_iface_t * csp_can_socketcan_init(const char * device, unsigned int node_id, int bitrate, bool promisc) {
	csp_iface_t * return_iface;
	int res = csp_can_socketcan_open_and_add_interface(device, CSP_IF_CAN_DEFAULT_NAME, node_id, bitrate, promisc, &return_iface);
	return (res == CSP_ERR_NONE) ? return_iface : NULL;
}

int csp_can_socketcan_stop(csp_iface_t * iface) {
	can_context_t * ctx = iface->driver_data;

	int error = pthread_cancel(ctx->rx_thread);
	if (error != 0) {
		csp_print("%s[%s]: pthread_cancel() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		return CSP_ERR_DRIVER;
	}
	error = pthread_join(ctx->rx_thread, NULL);
	if (error != 0) {
		csp_print("%s[%s]: pthread_join() failed, error: %s\n", __func__, ctx->name, strerror(errno));
		return CSP_ERR_DRIVER;
	}
	socketcan_free(ctx);
	return CSP_ERR_NONE;
}
