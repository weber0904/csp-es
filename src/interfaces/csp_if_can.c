#include <csp/interfaces/csp_if_can.h>

#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <stdio.h>

#include <csp/csp.h>
#include <csp/csp_id.h>

#include "csp_if_can_pbuf.h"

/**
 * TESTING:
 *
 * Create a virtual CAN network interface with a specific name 'vcan42':
 *    $ sudo ip link add dev vcan42 type vcan
 *    $ sudo ip link set dev vcan42 down
 *    $ sudo ip link set dev vcan42 up type can
 *
 */

#define CAN_CLASSIC_FRAME_SIZE 8
#define CAN_FD_FRAME_SIZE 64

/**
 * CFP 1.x defines
 */
#define CFP1_CSP_HEADER_OFFSET 0
#define CFP1_CSP_HEADER_SIZE   4
#define CFP1_DATA_LEN_OFFSET   4
#define CFP1_DATA_LEN_SIZE     2
#define CFP1_DATA_OFFSET       6
#define CFP1_DATA_SIZE_BEGIN   2
#define CFP1_DATA_SIZE_MORE    8

/* CFP type */
enum cfp_frame_t {
	/* First CFP fragment of a CSP packet */
	CFP_BEGIN = 0,
	/* Remaining CFP fragment(s) of a CSP packet */
	CFP_MORE = 1
};

static int cfp2_trace_enabled(void) {
	static int initialized = 0;
	static int enabled = 0;

	if (!initialized) {
		const char * value = getenv("COMM_CSP_CAN_CFP2_TRACE");
		enabled = (value != NULL) && (value[0] != '\0') && (strcmp(value, "0") != 0);
		initialized = 1;
	}

	return enabled;
}

static uint8_t csp_can_frame_size(const csp_iface_t * iface) {
	if ((iface == NULL) || (iface->interface_data == NULL)) {
		return CAN_CLASSIC_FRAME_SIZE;
	}

	const csp_can_interface_data_t * ifdata = iface->interface_data;
	if ((ifdata->frame_dlen == 0) || (ifdata->frame_dlen > CAN_FD_FRAME_SIZE)) {
		return CAN_CLASSIC_FRAME_SIZE;
	}

	return ifdata->frame_dlen;
}

static uint8_t csp_can_classic_frame_size(const csp_iface_t * iface) {
	if ((iface == NULL) || (iface->interface_data == NULL)) {
		return CAN_CLASSIC_FRAME_SIZE;
	}

	const csp_can_interface_data_t * ifdata = iface->interface_data;
	if ((ifdata->classic_frame_dlen == 0) || (ifdata->classic_frame_dlen > CAN_CLASSIC_FRAME_SIZE)) {
		return CAN_CLASSIC_FRAME_SIZE;
	}

	return ifdata->classic_frame_dlen;
}

uint16_t csp_can_get_dest_from_id(uint32_t id) {
	if (csp_conf.version == 1) {
		return CFP_DST(id);
	}

	return (uint16_t)((id >> CFP2_DST_OFFSET) & CFP2_DST_MASK);
}

int csp_can_dest_uses_canfd(const csp_iface_t * iface, uint16_t dest) {
	if ((iface == NULL) || (iface->interface_data == NULL)) {
		return 0;
	}

	const csp_can_interface_data_t * ifdata = iface->interface_data;
	if (csp_can_frame_size(iface) <= CAN_CLASSIC_FRAME_SIZE) {
		return 0;
	}

	if (ifdata->canfd_dest_allowlist_count == 0) {
		return 1;
	}

	for (uint8_t i = 0; i < ifdata->canfd_dest_allowlist_count; i++) {
		if (ifdata->canfd_dest_allowlist[i] == dest) {
			return 1;
		}
	}

	return 0;
}

static int csp_can_dport_uses_canfd(const csp_iface_t * iface, uint8_t dport) {
	if ((iface == NULL) || (iface->interface_data == NULL)) {
		return 0;
	}

	const csp_can_interface_data_t * ifdata = iface->interface_data;
	if (csp_can_frame_size(iface) <= CAN_CLASSIC_FRAME_SIZE) {
		return 0;
	}

	if (ifdata->canfd_dport_allowlist_count == 0) {
		return 1;
	}

	for (uint8_t i = 0; i < ifdata->canfd_dport_allowlist_count; i++) {
		if (ifdata->canfd_dport_allowlist[i] == dport) {
			return 1;
		}
	}

	return 0;
}

static uint8_t csp_can_tx_frame_size_for_dest_port(const csp_iface_t * iface, uint16_t dest, uint8_t dport) {
	if (csp_can_dest_uses_canfd(iface, dest) && csp_can_dport_uses_canfd(iface, dport)) {
		return csp_can_frame_size(iface);
	}

	return csp_can_classic_frame_size(iface);
}

uint8_t csp_can_tx_frame_size(const csp_iface_t * iface, uint16_t dest) {
	return csp_can_tx_frame_size_for_dest_port(iface, dest, 0U);
}

static int cfp2_trace_dport_filter(void) {
	static int initialized = 0;
	static int filter = -1;

	if (!initialized) {
		const char * value = getenv("COMM_CSP_CAN_CFP2_TRACE_DPORT");
		if ((value != NULL) && (value[0] != '\0')) {
			char * end = NULL;
			long parsed = strtol(value, &end, 10);
			if ((end != value) && (*end == '\0') && (parsed >= 0) && (parsed <= 63)) {
				filter = (int) parsed;
			}
		}
		initialized = 1;
	}

	return filter;
}

static int cfp2_extract_dport_from_header_extension(const uint8_t * header_extension) {
	if (header_extension == NULL) {
		return -1;
	}

	uint32_t value = 0;
	memcpy(&value, header_extension, sizeof(value));
	value = be32toh(value);
	return (value >> CFP2_DPORT_OFFSET) & CFP2_DPORT_MASK;
}

static int cfp2_trace_matches_dport(const int dport) {
	const int filter = cfp2_trace_dport_filter();
	return (filter < 0) || (filter == dport);
}

static void cfp2_trace(const char * phase,
					   const uint32_t id,
					   const uint8_t dlc,
					   const int dport,
					   const unsigned int frame_length,
					   const unsigned int packet_length,
					   const unsigned int frag_total,
					   const unsigned int expected_frag_total) {
	if (!cfp2_trace_enabled() || !cfp2_trace_matches_dport(dport)) {
		return;
	}

	csp_print("CFP2 trace: phase=%s dst=%u sender=%u sc=%u fc=%u begin=%u end=%u dlc=%u dport=%d frame-length=%u packet-length=%u frag-total=%u expected-frag-total=%u\n",
			  phase,
			  (unsigned int)((id >> CFP2_DST_OFFSET) & CFP2_DST_MASK),
			  (unsigned int)((id >> CFP2_SENDER_OFFSET) & CFP2_SENDER_MASK),
			  (unsigned int)((id >> CFP2_SC_OFFSET) & CFP2_SC_MASK),
			  (unsigned int)((id >> CFP2_FC_OFFSET) & CFP2_FC_MASK),
			  (unsigned int)((id >> CFP2_BEGIN_OFFSET) & CFP2_BEGIN_MASK),
			  (unsigned int)((id >> CFP2_END_OFFSET) & CFP2_END_MASK),
			  (unsigned int)dlc,
			  dport,
			  frame_length,
			  packet_length,
			  frag_total,
			  expected_frag_total);
}

static int csp_can1_rx(csp_iface_t * iface, uint32_t id, const uint8_t * data, uint8_t dlc, int * task_woken) {

	/* Test: random packet loss */
	// if (0) {
	// 	int random = rand();
	// 	if (random < RAND_MAX * 0.00005) {
	// 		return CSP_ERR_DRIVER;
	// 	}
	// }

	csp_can_interface_data_t * ifdata = iface->interface_data;

	/* Bind incoming frame to a packet buffer */
	csp_packet_t * packet = csp_can_pbuf_find(ifdata, id, CFP_ID_CONN_MASK, task_woken);
	if (packet == NULL) {
		if (CFP_TYPE(id) == CFP_BEGIN) {
			packet = csp_can_pbuf_new(ifdata, id, task_woken);
		} else {
			iface->frame++;
			return CSP_ERR_INVAL;
		}
	}

	/* Reset frame data offset */
	uint8_t offset = 0;

	switch (CFP_TYPE(id)) {

		case CFP_BEGIN:

			/* Discard packet if DLC is less than CSP id + CSP length fields */
			if (dlc < (sizeof(uint32_t) + sizeof(uint16_t))) {
				csp_dbg_can_errno = CSP_DBG_CAN_ERR_SHORT_BEGIN;
				iface->frame++;
				csp_can_pbuf_free(ifdata, packet, 1, task_woken);
				break;
			}

			csp_id_setup_rx(packet);

			/* Copy CSP identifier (header) */
			memcpy(packet->frame_begin, data, sizeof(uint32_t));
			packet->frame_length += sizeof(uint32_t);

			csp_id_strip(packet);

			/* Copy CSP length (of data) */
			memcpy(&(packet->length), data + sizeof(uint32_t), sizeof(packet->length));
			packet->length = be16toh(packet->length);

			/* Overflow: check if incoming frame data length is larger than buffer length  */
			if (packet->length > sizeof(packet->data)) {
				iface->rx_error++;
				csp_can_pbuf_free(ifdata, packet, 1, task_woken);
				break;
			}

			/* Reset RX count */
			packet->rx_count = 0;

			/* Set offset to prevent CSP header from being copied to CSP data */
			offset = sizeof(uint32_t) + sizeof(uint16_t);

			/* Set remain field - increment to include begin packet */
			packet->remain = CFP_REMAIN(id) + 1;

			/* FALLTHROUGH */

		case CFP_MORE:

			/* Check 'remain' field match */
			if ((uint16_t) CFP_REMAIN(id) != packet->remain - 1) {
				csp_dbg_can_errno = CSP_DBG_CAN_ERR_FRAME_LOST;
				csp_can_pbuf_free(ifdata, packet, 1, task_woken);
				iface->frame++;
				break;
			}

			/* Decrement remaining frames */
			packet->remain--;

			/* Check for overflow */
			if ((packet->rx_count + dlc - offset) > packet->length) {
				csp_dbg_can_errno = CSP_DBG_CAN_ERR_RX_OVF;
				iface->frame++;
				csp_can_pbuf_free(ifdata, packet, 1, task_woken);
				break;
			}

			/* Copy dlc bytes into buffer */
			memcpy(&packet->data[packet->rx_count], data + offset, dlc - offset);
			packet->rx_count += dlc - offset;

			/* Check if more data is expected */
			if (packet->rx_count != packet->length)
				break;

			/* Rewrite incoming L2 broadcast to local node */
			if (packet->id.dst == 0x1F) {
				packet->id.dst = iface->addr;
			}

			/* Free packet buffer */
			csp_can_pbuf_free(ifdata, packet, 0, task_woken);

			/* Data is available */
			csp_qfifo_write(packet, iface, task_woken);

			break;

		default:
			csp_dbg_can_errno = CSP_DBG_CAN_ERR_UNKNOWN;
			csp_can_pbuf_free(ifdata, packet, 1, task_woken);
			break;
	}

	return CSP_ERR_NONE;
}

static int csp_can1_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	(void)from_me; /* Avoid compiler warnings about unused parameter */

	/* Loopback */
	if (packet->id.dst == iface->addr) {
		csp_qfifo_write(packet, iface, NULL);
		return CSP_ERR_NONE;
	}

	csp_can_interface_data_t * ifdata = iface->interface_data;

	/* Get an unique CFP id - this should be locked to prevent access from multiple tasks */
	const uint32_t ident = ifdata->cfp_packet_counter++;

	/* Figure out destination node based on routing entry */
	const uint8_t dest = (via != CSP_NO_VIA_ADDRESS) ? via : packet->id.dst;

	uint32_t can_id = 0;
	uint8_t data_bytes = 0;
	const uint8_t frame_size = csp_can_tx_frame_size(iface, dest);
	uint8_t frame_buf[CAN_FD_FRAME_SIZE];

	/**
	 * CSP 1.x Frame Header:
	 * Data offset is always 6.
	 */
	can_id = (CFP_MAKE_SRC(packet->id.src) |
			  CFP_MAKE_DST(dest) |
			  CFP_MAKE_ID(ident) |
			  CFP_MAKE_TYPE(CFP_BEGIN) |
			  CFP_MAKE_REMAIN((packet->length + CFP1_DATA_OFFSET - 1) / frame_size));

	/**
	 * CSP 1.x Data field
	 *
	 * 4 byte CSP 1.0 header
	 * 2 byte length field
	 * 2 byte data (optional)
	 */

	/* Copy CSP 1.x headers and data: Always 4 bytes */
	csp_id_prepend(packet);
	memcpy(frame_buf + CFP1_CSP_HEADER_OFFSET, packet->frame_begin, CFP1_CSP_HEADER_SIZE);

	/* Copy length field, always 2 bytes */
	uint16_t csp_length_be = htobe16(packet->length);
	memcpy(frame_buf + CFP1_DATA_LEN_OFFSET, &csp_length_be, CFP1_DATA_LEN_SIZE);

	/* Calculate number of data bytes. Max 2 bytes possible */
	const uint8_t begin_data_capacity = (frame_size > CFP1_DATA_OFFSET) ? (frame_size - CFP1_DATA_OFFSET) : 0;
	data_bytes = (packet->length <= begin_data_capacity) ? packet->length : begin_data_capacity;
	memcpy(frame_buf + CFP1_DATA_OFFSET, packet->data, data_bytes);

	/* Increment tx counter */
	uint16_t tx_count = data_bytes;

	const csp_can_driver_tx_t tx_func = ifdata->tx_func;

	/* Send first frame */
	if ((tx_func)(iface->driver_data, can_id, frame_buf, CFP1_DATA_OFFSET + data_bytes) != CSP_ERR_NONE) {
		iface->tx_error++;
		/* Does not free on return */
		return CSP_ERR_DRIVER;
	}

	/* Send next frames if not complete */
	while (tx_count < packet->length) {

		/**
		 * CSP 1.x Frame Header:
		 * Data offset is always 6.
		 */

		/* Calculate frame data bytes */
		data_bytes = (packet->length - tx_count >= frame_size) ? frame_size : packet->length - tx_count;

		/* Prepare identifier */
		can_id = (CFP_MAKE_SRC(packet->id.src) |
				  CFP_MAKE_DST(dest) |
				  CFP_MAKE_ID(ident) |
				  CFP_MAKE_TYPE(CFP_MORE) |
				  CFP_MAKE_REMAIN((packet->length - tx_count - data_bytes + frame_size - 1) / frame_size));

		/* Increment tx counter */
		tx_count += data_bytes;

		/* Send frame */
		if ((tx_func)(iface->driver_data, can_id, packet->data + tx_count - data_bytes, data_bytes) != CSP_ERR_NONE) {
			iface->tx_error++;
			/* Does not free on return */
			return CSP_ERR_DRIVER;
		}
	}

	csp_buffer_free(packet);

	return CSP_ERR_NONE;
}

static int csp_can2_rx(csp_iface_t * iface, uint32_t id, const uint8_t * data, uint8_t dlc, int * task_woken) {

	csp_can_interface_data_t * ifdata = iface->interface_data;
	const uint8_t frame_size = csp_can_frame_size(iface);
	int trace_dport = -1;

	/* Bind incoming frame to a packet buffer */
	csp_packet_t * packet = csp_can_pbuf_find(ifdata, id, CFP2_ID_CONN_MASK, task_woken);
	if (packet == NULL) {
		if (id & (CFP2_BEGIN_MASK << CFP2_BEGIN_OFFSET)) {
			packet = csp_can_pbuf_new(ifdata, id, task_woken);
		} else {
			iface->frame++;
			return CSP_ERR_INVAL;
		}
	}


	/* BEGIN */
	if (id & (CFP2_BEGIN_MASK << CFP2_BEGIN_OFFSET)) {

		/* Discard packet if DLC is less than CSP id + CSP length fields */
		if (dlc < 4) {
			csp_dbg_can_errno = CSP_DBG_CAN_ERR_SHORT_BEGIN;
			iface->frame++;
			csp_can_pbuf_free(ifdata, packet, 1, task_woken);
			return CSP_ERR_INVAL;
		}

		csp_id_setup_rx(packet);

		/* Copy first 2 bytes from CFP 2.0 header:
		 * Because the id field has already been converted in memory to a 32-bit
		 * host-order field, extract the first two bytes and convert back to
		 * network order */
		uint16_t first_two = id >> CFP2_DST_OFFSET;
		first_two = htobe16(first_two);
		memcpy(packet->frame_begin, &first_two, 2);

		/* Copy next 4 from data, the data field is in network order */
		memcpy(&packet->frame_begin[2], data, 4);

		packet->frame_length = 6;
		packet->length = 0;
		packet->remain = 1;
		trace_dport = cfp2_extract_dport_from_header_extension(data);

		/* Move RX offset for incoming data */
		data += 4;
		dlc -= 4;

		/* Set next expected fragment counter to be 1 */
		packet->rx_count = 1;

		/* FRAGMENT */
	} else {

		int fragment_counter = (id >> CFP2_FC_OFFSET) & CFP2_FC_MASK;

		/* Check fragment counter is increasing:
		 * We abuse / reuse the rx_count pbuf field
		 * (Note this could be done using csp buffers instead) */
		if ((packet->rx_count) != fragment_counter) {
			csp_dbg_can_errno = CSP_DBG_CAN_ERR_FRAME_LOST;
			csp_can_pbuf_free(ifdata, packet, 1, task_woken);
			iface->frame++;
			return CSP_ERR_INVAL;
		}

		/* Increment expected next fragment counter:
		 * and with the mask in order to wrap around */
		packet->rx_count = (packet->rx_count + 1) & CFP2_FC_MASK;
		packet->remain++;
	}

	if (trace_dport < 0) {
		trace_dport = cfp2_extract_dport_from_header_extension(&packet->frame_begin[2]);
	}

	/* Check for overflow. The frame input + dlc must not exceed the end of the packet data field */
	if (&packet->frame_begin[packet->frame_length] + dlc > &packet->data[sizeof(packet->data)]) {
		csp_dbg_can_errno = CSP_DBG_CAN_ERR_RX_OVF;
		iface->rx_error++;
		csp_can_pbuf_free(ifdata, packet, 1, task_woken);
		return CSP_ERR_INVAL;
	}

	/* Copy dlc bytes into buffer */
	memcpy(&packet->frame_begin[packet->frame_length], data, dlc);
	packet->frame_length += dlc;
	cfp2_trace("rx-fragment", id, dlc, trace_dport, packet->frame_length, packet->frame_length >= 6 ? (packet->frame_length - 6) : 0, packet->remain, 0);

	/* END */
	if (id & (CFP2_END_MASK << CFP2_END_OFFSET)) {
		const unsigned int frame_length_before_strip = packet->frame_length;
		const unsigned int packet_length_before_strip = frame_length_before_strip >= 6 ? (frame_length_before_strip - 6) : 0;

		/* Parse CSP header into csp_id type */
		csp_id_strip(packet);
		cfp2_trace("rx-end", id, dlc, packet->id.dport, frame_length_before_strip, packet_length_before_strip, packet->remain,
				   (packet_length_before_strip <= (unsigned int)(frame_size >= 4U ? (frame_size - 4U) : 0U))
					   ? 1U
					   : (2U + (unsigned int)((packet_length_before_strip - (unsigned int)(frame_size - 4U) - 1U) / frame_size)));

		/* Rewrite incoming L2 broadcast to local node */
		if (packet->id.dst == 0x3FFF) {
			packet->id.dst = iface->addr;
		}

		/* Free packet buffer */
		csp_can_pbuf_free(ifdata, packet, 0, task_woken);

		/* Data is available */
		csp_qfifo_write(packet, iface, task_woken);

	}

	return CSP_ERR_NONE;
}

static int csp_can2_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {
	/* Avoid compiler warnings about unused parameter */
	(void)via;
	(void)from_me;

	/* Loopback */
	if (packet->id.dst == iface->addr) {
		csp_qfifo_write(packet, iface, NULL);
		return CSP_ERR_NONE;
	}

	csp_can_interface_data_t * ifdata = iface->interface_data;
	const uint8_t frame_size = csp_can_tx_frame_size_for_dest_port(iface, packet->id.dst, packet->id.dport);

	/* Setup counters */
	int sender_count = ifdata->cfp_packet_counter++;
	int tx_count = 0;
	const unsigned int expected_frag_total =
		(packet->length <= (unsigned int)(frame_size >= 4U ? (frame_size - 4U) : 0U))
			? 1U
			: (2U + (unsigned int)((packet->length - (unsigned int)(frame_size - 4U) - 1U) / frame_size));

	uint32_t can_id = 0;
	uint8_t frame_buf_inp = 0;

	/* Pack mandatory fields of header */
	can_id = (((packet->id.pri & CFP2_PRIO_MASK) << CFP2_PRIO_OFFSET) |
			  ((packet->id.dst & CFP2_DST_MASK) << CFP2_DST_OFFSET) |
			  ((iface->addr & CFP2_SENDER_MASK) << CFP2_SENDER_OFFSET) |
			  ((sender_count & CFP2_SC_MASK) << CFP2_SC_OFFSET) |
			  ((1 & CFP2_BEGIN_MASK) << CFP2_BEGIN_OFFSET));

	/* Pack the rest of the CSP header in the first 32-bit of data */
	uint32_t frame_buf_mem[(CAN_FD_FRAME_SIZE + sizeof(uint32_t) - 1) / sizeof(uint32_t)];
	uint8_t * frame_buf = (uint8_t *) frame_buf_mem;
	uint32_t * header_extension = (uint32_t *)frame_buf_mem;

	*header_extension = (((packet->id.src & CFP2_SRC_MASK) << CFP2_SRC_OFFSET) |
						 ((packet->id.dport & CFP2_DPORT_MASK) << CFP2_DPORT_OFFSET) |
						 ((packet->id.sport & CFP2_SPORT_MASK) << CFP2_SPORT_OFFSET) |
						 ((packet->id.flags & CFP2_FLAGS_MASK) << CFP2_FLAGS_OFFSET));

	/* Convert to network byte order */
	*header_extension = htobe32(*header_extension);

	frame_buf_inp += 4;

	/* Copy first bytes of data field (max 4) */
	const int begin_data_capacity = (frame_size >= 4U) ? (frame_size - 4U) : 0;
	int data_bytes = (packet->length >= begin_data_capacity) ? begin_data_capacity : packet->length;
	memcpy(frame_buf + frame_buf_inp, packet->data, data_bytes);
	frame_buf_inp += data_bytes;
	tx_count = data_bytes;

	/* Check for end condition */
	if (tx_count == packet->length) {
		can_id |= ((1 & CFP2_END_MASK) << CFP2_END_OFFSET);
	}

	/* Send first frame now */
	cfp2_trace("tx-begin", can_id, frame_buf_inp, packet->id.dport, packet->frame_length, packet->length, 1U, expected_frag_total);
	if ((ifdata->tx_func)(iface->driver_data, can_id, frame_buf, frame_buf_inp) != CSP_ERR_NONE) {
		iface->tx_error++;
		/* Does not free on return */
		return CSP_ERR_DRIVER;
	}

	/* Send next fragments if not complete */
	int fragment_count = 1;
	unsigned int frag_total = 1U;
	while (tx_count < packet->length) {

		/* Pack mandatory fields of header */
		can_id = (((packet->id.pri & CFP2_PRIO_MASK) << CFP2_PRIO_OFFSET) |
				  ((packet->id.dst & CFP2_DST_MASK) << CFP2_DST_OFFSET) |
				  ((iface->addr & CFP2_SENDER_MASK) << CFP2_SENDER_OFFSET) |
				  ((sender_count & CFP2_SC_MASK) << CFP2_SC_OFFSET));

		/* Set and increment fragment count */
		can_id |= (fragment_count++ & CFP2_FC_MASK) << CFP2_FC_OFFSET;

		/* Calculate frame data bytes */
		data_bytes = (packet->length - tx_count >= frame_size) ? frame_size : packet->length - tx_count;

		/* Check for end condition */
		if (tx_count + data_bytes == packet->length) {
			can_id |= ((1 & CFP2_END_MASK) << CFP2_END_OFFSET);
		}

		/* Send frame */
		frag_total++;
		cfp2_trace("tx-fragment", can_id, data_bytes, packet->id.dport, packet->frame_length, packet->length, frag_total, expected_frag_total);
		if ((ifdata->tx_func)(iface->driver_data, can_id, packet->data + tx_count, data_bytes) != CSP_ERR_NONE) {
			iface->tx_error++;
			/* Does not free on return */
			return CSP_ERR_DRIVER;
		}

		/* Increment tx counter */
		tx_count += data_bytes;
	}

	csp_buffer_free(packet);

	return CSP_ERR_NONE;
}

int csp_can_add_interface(csp_iface_t * iface) {

	if ((iface == NULL) || (iface->name == NULL) || (iface->interface_data == NULL)) {
		return CSP_ERR_INVAL;
	}

	csp_can_interface_data_t * ifdata = iface->interface_data;
	if (ifdata->tx_func == NULL) {
		return CSP_ERR_INVAL;
	}

	ifdata->cfp_packet_counter = 0;
	if (ifdata->classic_frame_dlen == 0) {
		ifdata->classic_frame_dlen = CAN_CLASSIC_FRAME_SIZE;
	}
	if (ifdata->frame_dlen == 0) {
		ifdata->frame_dlen = CAN_CLASSIC_FRAME_SIZE;
	}

	if (csp_conf.version == 1) {
		iface->nexthop = csp_can1_tx;
	} else {
		iface->nexthop = csp_can2_tx;
	}

	csp_iflist_add(iface);

	return CSP_ERR_NONE;
}

int csp_can_remove_interface(csp_iface_t * iface) {

	if (iface == NULL) {
		return CSP_ERR_INVAL;
	}

	csp_iflist_remove(iface);

	return CSP_ERR_NONE;
}

int csp_can_rx(csp_iface_t * iface, uint32_t id, const uint8_t * data, uint8_t dlc, int * task_woken) {
	if (csp_conf.version == 1) {
		return csp_can1_rx(iface, id, data, dlc, task_woken);
	} else {
		return csp_can2_rx(iface, id, data, dlc, task_woken);
	}
}
