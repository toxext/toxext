#include "toxext.h"
#include "toxext_util.h"

#include <tox/tox.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define TOXEXT_MAGIC ((int32_t)0xac03dffe)
#define TOXEXT_MAGIC_SIZE 4
#define TOXEXT_SEGMENT_HEADER_SIZE 3
#define TOXEXT_PROTOCOL_VERSION 0
#define TOXEXT_NEGOTIATE_SEGMENT_SIZE 22
#define TOXEXT_NEGOTIATE_RESPONSE_SEGMENT_SIZE 4
#define UUID_SIZE 16

#ifdef swap
#undef swap
#endif

/**
 * Swap macro stolen from linux kernel
 */
#define swap(x, y)                                                             \
	do {                                                                   \
		unsigned char swap_temp[sizeof(x) == sizeof(y) ?               \
						(signed)sizeof(x) :            \
						-1];                           \
		memcpy(swap_temp, &y, sizeof(x));                              \
		memcpy(&y, &x, sizeof(x));                                     \
		memcpy(&x, swap_temp, sizeof(x));                              \
	} while (0)

/**
 * Generic function like macro that swaps an item with the last element
 */
#define toxext_move_item_to_end(array, size, item, comparator)                 \
	do {                                                                   \
		for (size_t __i = 0; __i < size; ++__i) {                      \
			if (comparator(&array[__i], item)) {                   \
				swap(array[__i], array[size - 1]);             \
				break;                                         \
			}                                                      \
		}                                                              \
	} while (0)

typedef uint16_t ExtensionConnectionId;

/**
 * Mapping of a friend to a connection_id. This is used to avoid having to send
 * UUIDs of our extension in every packet. Instead we negotiate an extension id
 * for each friend and use that to indicate which extension we are talking to
 */
struct ToxExtConnection {
	uint32_t friend_id;
	ExtensionConnectionId connection_id;
	struct ToxExtExtension *extension;
};

/**
 * Handle to our extension manager. We should have one of these per toxcore
 * instance
 */
struct ToxExt {
	struct Tox *tox;
	/* An array of registered extensions */
	struct ToxExtExtension **extensions;
	size_t num_extensions;

	/**
	 * This maps received packets back to an extension. Note that we should *not*
	 * use this for the sender path as the connection holds *their* connection id.
	 * We told them what our extension id was already so on the sender path we just
	 * use ours again.
	 */
	struct ToxExtConnection *connections;
	size_t num_connections;

	/**
	 * Sometimes toxcore will not be able to send our entire packet list at one time.
	 * In this case we need to defer sending packets until toxcore has serviced more
	 * packets. This list is serviced in toxext_iterate calls
	 */
	struct ToxExtPacketList **deferred_packets;
	size_t num_deferred_packets;
};

struct ToxExtExtension {
	/* Reference to parent ToxExt */
	struct ToxExt *toxext;
	/* UUID of current extension */
	uint8_t uuid[UUID_SIZE];
	/* Globally unique ID */
	uint16_t id;
	/* Callback for when we receive a packet related to this extension */
	toxext_recv_callback recv_cb;
	/* Callback for when we finish negotiation with a friend */
	toxext_negotiate_connection_cb negotiate_extension_cb;
	/* Userdata to pass back when we receive a packet */
	void *userdata;
};

/**
 * ToxExt representatio of a toxcore packet. This packet may contain several
 * toxext extension segments, and multiple of these may be sent at once in a
 * single ToxExtPacketList
 */
struct ToxExtPacket {
	uint8_t buf[TOX_MAX_CUSTOM_PACKET_SIZE];
	size_t len;
};

/**
 * A list of ToxExt packets. We may have folded multiple extension segments
 * into a single ToxExtPacket. Internally we will refer to each segment added
 * with toxext_segment_append as an extension segment
 */
struct ToxExtPacketList {
	struct ToxExt *toxext;
	struct ToxExtPacket *packets;
	size_t pending_packet;
	size_t num_packets;
	uint32_t friend_id;
};

enum ToxExtSegmentType {
	TOXEXT_SEGMENT_NEGOTIATE,
	TOXEXT_SEGMENT_NEGOTIATE_RESPONSE,
	TOXEXT_SEGMENT_REVOKE,
	/* Extensions will start identifying themselves at TOXEXT_SEGMENT_CUSTOM_START */
	TOXEXT_SEGMENT_CUSTOM_START
};

enum ToxExtNegotiateSegmentType {
	TOXEXT_NEGOTIATE_REQUEST,
	TOXEXT_NEGOTIATE_SUPPORTED,
};

struct ExtensionConnectionAndFriendId {
	ExtensionConnectionId id;
	uint32_t friend_id;
};

/**
 * Determines whether a given ToxExtConnection has an associated extension and
 * friend_id. Used as a comparator for sorting connections
 */
static bool connection_has_connection_id_and_friend_id(
	struct ToxExtConnection *connection,
	struct ExtensionConnectionAndFriendId *ext_and_friend_id)
{
	return connection->friend_id == ext_and_friend_id->friend_id &&
	       connection->connection_id == ext_and_friend_id->id;
}

struct ToxExtExtensionAndFriendId {
	struct ToxExtExtension *extension;
	uint32_t friend_id;
};

/**
 * Determines whether a given ToxExtConnection has an associated extension and
 * friend_id. Used as a comparator for sorting connections
 */
static bool connection_has_extension_and_friend_id(
	struct ToxExtConnection *connection,
	struct ToxExtExtensionAndFriendId *ext_and_friend_id)
{
	return connection->friend_id == ext_and_friend_id->friend_id &&
	       connection->extension == ext_and_friend_id->extension;
}

static uint16_t toxext_read_segment_id(uint8_t const *segment)
{
	/*
	 * The segment id is the first 13 bits of the segment. See DESIGN.md for
	 * more information
	 */
	uint16_t id = 0;
	id |= segment[0] << 8;
	id |= segment[1] & 0xf8;
	return id >> 3;
}

static uint16_t toxext_read_segment_size(uint8_t const *segment)
{
	/**
	 * The segment size is 11 bits starting at bit 14. See DESIGN.md for more
	 * information
	 */
	uint16_t size = 0;
	size |= (segment[1] & 0x7) << 8;
	size |= segment[2];
	return size;
}

static void toxext_write_segment(uint16_t id, uint8_t const *data, size_t size,
				 uint8_t *pBuf)
{
	assert(size <= TOXEXT_MAX_SEGMENT_SIZE);
	/* The segment type is 13 bits, so the maximum ID we can use is 2^13 - 1*/
	assert(id < (1 << 13) - 1);

	/*
	 * The segment ID does not sit cleanly on a byte boundary. Shift and mask to
	 * pack it into the first 13 bits of the packet
	 */
	uint16_t shifted_id = id << 3;
	pBuf[0] = (shifted_id >> 8) & 0xff;
	pBuf[1] = (shifted_id) & 0xff;

	/*
	 * Segment size is 11 bits and sits cleanly with the lower 8bits sitting on
	 * the byte boundary between bytes 2/3. Mask off the top 3 bits and put them
	 * in byte 1. The rest fit in byte 2. See DESIGN.md for more information
	 */
	pBuf[1] |= (size & 0x0700) >> 8;
	pBuf[2] = (size & 0x00ff);

	memcpy(pBuf + 3, data, size);
}

#define toxext_read_uint16(buffer) toxext_read_from_buf(uint16_t, buffer, 2)
#define toxext_write_uint16(buffer, i) toxext_write_to_buf(i, buffer, 2)
#define toxext_read_int32(buffer) toxext_read_from_buf(int32_t, buffer, 4)
#define toxext_write_int32(buffer, i) toxext_write_to_buf(i, buffer, 4)

/**
 * Initializes a toxcore packet with the toxext magic
 */
static int toxext_init_packet_header(struct ToxExtPacket *packet_buf)
{
	toxext_write_int32(packet_buf->buf, TOXEXT_MAGIC);
	packet_buf->len = 4;

	return TOXEXT_SUCCESS;
}

/**
 * Appends a toxcore packet with an extension segment.
 * This must fit in a single toxcore packet
 */
static int toxext_append_segment_data_to_packet(struct ToxExtPacket *packet,
					enum ToxExtSegmentType segment_type,
					void const *data, size_t size)
{
	size_t const total_size =
		packet->len + size + TOXEXT_SEGMENT_HEADER_SIZE;

	if (total_size > TOX_MAX_CUSTOM_PACKET_SIZE) {
		return TOXEXT_DATA_TOO_LARGE;
	}

	assert(TOXEXT_MAX_SEGMENT_SIZE <= INT32_MAX);

	toxext_write_segment(segment_type, data, size,
			     &packet->buf[packet->len]);

	packet->len += TOXEXT_SEGMENT_HEADER_SIZE;
	packet->len += size;

	/* We checked this at the start, just make sure we didn't make a mistake */
	assert(packet->len <= TOX_MAX_CUSTOM_PACKET_SIZE);

	return TOXEXT_SUCCESS;
}

/**
 * Extends packet list's packet count by 1
 */
static int toxext_append_packet_to_packet_list(struct ToxExtPacketList *packet_list)
{
	struct ToxExtPacket *new_packet =
		realloc(packet_list->packets, (packet_list->num_packets +
					  1) * sizeof(struct ToxExtPacket));

	if (!new_packet) {
		return TOXEXT_ALLOCATE_FAIL;
	}

	packet_list->packets = new_packet;
	packet_list->num_packets++;
	struct ToxExtPacket *last_packet =
		&packet_list->packets[packet_list->num_packets - 1];
	last_packet->len = 0;
	toxext_init_packet_header(last_packet);

	return TOXEXT_SUCCESS;
}

/**
 * Adds extension segment to the packet list. Note that segment_type may be an
 * extension ID. This will extend ToxExtPacketLists to be sent over multiple
 * toxcore packets if necessary, however the segment must still fit within a
 * single toxcore packet
 */
static int toxext_append_segment_to_packet_list(struct ToxExtPacketList *packet_list,
				     enum ToxExtSegmentType segment_type,
				     void const *data, size_t size)
{
	if (!packet_list) {
		return TOXEXT_INVALID_SEGMENT;
	}

	if (size > TOXEXT_MAX_SEGMENT_SIZE) {
		return TOXEXT_DATA_TOO_LARGE;
	}

	size_t total_size = packet_list->packets[packet_list->num_packets - 1].len +
			    size + TOXEXT_SEGMENT_HEADER_SIZE;

	if (total_size > TOX_MAX_CUSTOM_PACKET_SIZE) {
		int err;
		if ((err = toxext_append_packet_to_packet_list(packet_list))) {
			return err;
		}
	}

	struct ToxExtPacket *packet =
		&packet_list->packets[packet_list->num_packets - 1];

	return toxext_append_segment_data_to_packet(packet, segment_type, data,
					    size);
}

/**
 * Finds the first unused extension ID. This could be faster if we sorted our
 * extensions
 */
static uint32_t toxext_get_first_unused_id(struct ToxExt *toxext)
{
	uint16_t proposed_id = TOXEXT_SEGMENT_CUSTOM_START;
	size_t i = 0;

	while (i < toxext->num_extensions) {
		if (toxext->extensions[i]->id == proposed_id) {
			proposed_id++;
			i = 0;
		} else {
			i++;
		}
	}

	return proposed_id;
}

/**
 * Determines whether the extension pointed to by a is b. Used for sorting
 */
static bool toxext_is_same(struct ToxExtExtension **a,
			   struct ToxExtExtension *b)
{
	return *a == b;
}

struct ToxExt *toxext_init(struct Tox *tox)
{
	struct ToxExt *toxext = malloc(sizeof(struct ToxExt));
	toxext->tox = tox;
	toxext->extensions = NULL;
	toxext->num_extensions = 0;
	toxext->connections = NULL;
	toxext->num_connections = 0;
	toxext->deferred_packets = NULL;
	toxext->num_deferred_packets = 0;
	return toxext;
}

void toxext_free(struct ToxExt *toxext)
{
	free(toxext->connections);
	for (size_t i = 0; i < toxext->num_extensions; ++i) {
		free(toxext->extensions[i]);
	}
	free(toxext->extensions);
	free(toxext->deferred_packets);
	free(toxext);
}

void toxext_iterate(struct ToxExt *toxext)
{
	while (true) {
		size_t deferred_packet_size = toxext->num_deferred_packets;
		if (deferred_packet_size == 0) {
			break;
		}

		/* Always send element 0 since toxext_send will pop us off the top of the list */
		toxext_send(toxext->deferred_packets[0]);
		if (deferred_packet_size == toxext->num_deferred_packets) {
			/* We've sent all we can for this iteration */
			break;
		}
	}
}

struct ToxExtExtension *toxext_register(struct ToxExt *toxext,
					uint8_t const *uuid, void *userdata,
					toxext_recv_callback cb,
					toxext_negotiate_connection_cb neg_cb)
{
	struct ToxExtExtension *extension =
		malloc(sizeof(struct ToxExtExtension));

	extension->toxext = toxext;
	memcpy(extension->uuid, uuid, sizeof(extension->uuid));
	extension->id = toxext_get_first_unused_id(toxext);
	extension->recv_cb = cb;
	extension->negotiate_extension_cb = neg_cb;
	extension->userdata = userdata;

	struct ToxExtExtension **new_extensions = realloc(
		toxext->extensions, (toxext->num_extensions + 1) *
					    sizeof(struct ToxExtExtension *));

	if (new_extensions) {
		toxext->extensions = new_extensions;
		toxext->extensions[toxext->num_extensions] = extension;
		toxext->num_extensions++;
	} else {
		return NULL;
	}

	return extension;
}

void toxext_deregister(struct ToxExtExtension *extension)
{
	struct ToxExt *toxext = extension->toxext;

	/**
	 * Cleanup all existing connections For the time being this is pretty
	 * inefficient... but who cares
	 */
	for (size_t i = 0; i < toxext->num_connections; ++i) {
		if (toxext->connections[i].extension == extension) {
			toxext_revoke_connection(
				extension, toxext->connections[i].friend_id);
		}
	}

	toxext_move_item_to_end(toxext->extensions, toxext->num_extensions,
				extension, toxext_is_same);

	/**
	 * We should should probably handle this more gracefully, but if someone is
	 * putting us in this situation we hate them anyways
	 */
	assert(toxext->extensions[toxext->num_extensions - 1] == extension);

	free(extension);

	/* Even if we fail to realloc after we can still reduce our size */
	toxext->num_extensions--;

	struct ToxExtExtension **new_extensions = realloc(
		toxext->extensions,
		toxext->num_extensions * sizeof(struct ToxExtExtension *));

	if (new_extensions || toxext->num_extensions == 0) {
		toxext->extensions = new_extensions;
	}
}

/**
 * Maps a friend's connection id back to a connection we have with them
 */
static struct ToxExtConnection *
toxext_id_to_connection(struct ToxExt *toxext, ExtensionConnectionId id,
			uint32_t friend_id)
{
	for (size_t i = 0; i < toxext->num_connections; ++i) {
		struct ToxExtConnection *connection = &toxext->connections[i];
		if (connection->connection_id == id &&
		    connection->friend_id == friend_id) {
			return connection;
		}
	}

	return NULL;
}

static int toxext_insert_connection(struct ToxExt *toxext,
				    ExtensionConnectionId id,
				    struct ToxExtExtension *extension,
				    uint32_t friend_id)
{
	struct ToxExtConnection *connection =
		toxext_id_to_connection(toxext, id, friend_id);

	if (!connection) {
		struct ToxExtConnection *new_connections =
			realloc(toxext->connections,
				(toxext->num_connections + 1) *
					sizeof(struct ToxExtConnection));

		if (!new_connections) {
			return TOXEXT_ALLOCATE_FAIL;
		}
		toxext->connections = new_connections;
		toxext->num_connections++;
		connection = &toxext->connections[toxext->num_connections - 1];
		connection->friend_id = friend_id;
	}

	/* Uncondtionally update the connection with the new data */
	connection->connection_id = id;
	connection->extension = extension;

	return TOXEXT_SUCCESS;
}

static void toxext_remove_connection(struct ToxExt *toxext,
				     ExtensionConnectionId id,
				     uint32_t friend_id)
{
	/* Move connection to then end of the list for easy mangagement */
	struct ExtensionConnectionAndFriendId ext_and_friend_id = {
		.id = id, .friend_id = friend_id
	};

	toxext_move_item_to_end(toxext->connections, toxext->num_connections,
				&ext_and_friend_id,
				connection_has_connection_id_and_friend_id);

	/* Remove connection from list */
	struct ToxExtConnection *new_connections;
	/* If we fail to realloc we can still just not use that item */
	toxext->num_connections--;

	new_connections = realloc(toxext->connections,
				  toxext->num_connections *
					  sizeof(struct ToxExtConnection));

	if (new_connections || toxext->num_connections == 0) {
		toxext->connections = new_connections;
	}
}

/**
 * Maps a UUID back to a registered extension
 */
static struct ToxExtExtension *toxext_uuid_to_extension(struct ToxExt *toxext,
							uint8_t const *uuid)
{
	for (size_t i = 0; i < toxext->num_extensions; ++i) {
		if (memcmp(toxext->extensions[i]->uuid, uuid, UUID_SIZE) == 0) {
			return toxext->extensions[i];
		}
	}
	return NULL;
}

static struct ToxExtExtension *toxext_lookup_local_id(struct ToxExt *toxext,
						      uint16_t local_id)
{
	for (size_t i = 0; i < toxext->num_extensions; ++i) {
		if (toxext->extensions[i]->id == local_id) {
			return toxext->extensions[i];
		}
	}

	return NULL;
}

/**
 * Creates a toxext packet
 */
static struct ToxExtPacket *toxext_packet_create()
{
	struct ToxExtPacket *ret = malloc(sizeof(struct ToxExtPacket));
	if (ret) {
		ret->len = 0;
		toxext_init_packet_header(ret);
	}
	return ret;
}

struct ToxExtPacketList *toxext_packet_list_create(struct ToxExt *toxext,
						   uint32_t friend_id)
{
	struct ToxExtPacketList *packet_list =
		malloc(sizeof(struct ToxExtPacketList));

	packet_list->packets = toxext_packet_create();
	if (!packet_list->packets) {
		free(packet_list);
		return NULL;
	}

	packet_list->pending_packet = 0;
	packet_list->num_packets = 1;
	packet_list->friend_id = friend_id;
	packet_list->toxext = toxext;
	return packet_list;
}

/**
 * Frees a packet list along with all owned data inside
 */
static void toxext_packet_list_free(struct ToxExtPacketList *packet_list)
{
	free(packet_list->packets);

	/*
	 * Remove the packetlist from the deferred packets if necessary, note that we
	 * only check the first packet since we guarantee we send them in order
	 */
	if (packet_list->toxext->num_deferred_packets &&
	    *packet_list->toxext->deferred_packets == packet_list) {
		/* Slide all elements back by one to preserve order */
		memcpy(packet_list->toxext->deferred_packets,
		       packet_list->toxext->deferred_packets + 1,
		       packet_list->toxext->num_deferred_packets - 1);

		/* If we fail to realloc we can still just not use that item */
		packet_list->toxext->num_deferred_packets--;
		/* Remove connection from list */
		struct ToxExtPacketList **new_deferred_packets =
			realloc(packet_list->toxext->deferred_packets,
				packet_list->toxext->num_deferred_packets *
					sizeof(struct ToxExtPacketList *));

		if (new_deferred_packets ||
		    packet_list->toxext->num_deferred_packets == 0) {
			packet_list->toxext->deferred_packets = new_deferred_packets;
		}
	}

	free(packet_list);
}

int toxext_segment_append(struct ToxExtPacketList *packet /*in/out*/,
			 struct ToxExtExtension *extension, void const *data,
			 size_t size)
{
	return toxext_append_segment_to_packet_list(packet, extension->id, data, size);
}

static int toxext_packet_list_defer(struct ToxExtPacketList *packet_list)
{
	struct ToxExt *toxext = packet_list->toxext;

	/* Only check the first packet since we must send our deferred packets in order */
	if (toxext->num_deferred_packets > 0 &&
	    *toxext->deferred_packets == packet_list) {
		/* No work to do, we're already sending this deferred packet */
		return TOXEXT_SUCCESS;
	}

	struct ToxExtPacketList **new_deferred_packets =
		realloc(toxext->deferred_packets,
			(toxext->num_deferred_packets + 1) *
				sizeof(struct ToxExtPacketList *));

	if (!new_deferred_packets) {
		return TOXEXT_ALLOCATE_FAIL;
	}

	toxext->deferred_packets = new_deferred_packets;
	toxext->num_deferred_packets++;

	toxext->deferred_packets[toxext->num_deferred_packets - 1] = packet_list;

	return TOXEXT_SUCCESS;
}

int toxext_send(struct ToxExtPacketList *packet_list)
{
	/* FIXME: No test to verify this is right */
	if (packet_list->packets[0].len == TOXEXT_MAGIC_SIZE) {
		toxext_packet_list_free(packet_list);
		return TOXEXT_SUCCESS;
	}

	/* Ensure ordered packets by deferring this packet if there are already deferred packets */
	if (packet_list->toxext->num_deferred_packets > 0 &&
	    *packet_list->toxext->deferred_packets != packet_list) {
		toxext_packet_list_defer(packet_list);
		return TOXEXT_SUCCESS;
	}

	bool success = true;
	TOX_ERR_FRIEND_CUSTOM_PACKET err;
	for (size_t i = packet_list->pending_packet; i < packet_list->num_packets; ++i) {
		packet_list->pending_packet = i;

		struct ToxExtPacket *packet_buf = &packet_list->packets[i];
		bool packet_success = tox_friend_send_lossless_packet(
			packet_list->toxext->tox, packet_list->friend_id, packet_buf->buf,
			packet_buf->len, &err);

		success = success && packet_success;
		if (!success) {
			break;
		}
	}

	if (!success && err == TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ) {
		toxext_packet_list_defer(packet_list);
		/*
		 * In this case we want to flag to the caller that this was a success, we'll
		 * handle the rest later
		 */
		success = true;
	} else {
		toxext_packet_list_free(packet_list);
	}

	/**
	 * Error clobbering is kinda lame but our error types are different, we can
	 * propogate the toxcore error in an error* field later if we like
	 */
	if (!success) {
		return TOXEXT_SEND_FAILED;
	}

	return TOXEXT_SUCCESS;
}

bool is_toxext_packet(uint8_t const *data, size_t size)
{
	if (size < 4)
		return false;

	return toxext_read_int32(data) == TOXEXT_MAGIC;
}

struct ToxExtNegotiateRequest {
	uint8_t const *uuid;
	uint16_t remote_id;
};

static int
toxext_parse_negotiate_segment(uint8_t const *data, size_t size,
			      struct ToxExtNegotiateRequest *negotiate_request)
{
	if (size != TOXEXT_NEGOTIATE_SEGMENT_SIZE) {
		return TOXEXT_INVALID_SEGMENT;
	}

	uint8_t const *it = data;
	int32_t toxext_ver = toxext_read_int32(it);
	it += 4;

	if (toxext_ver != TOXEXT_PROTOCOL_VERSION) {
		return TOXEXT_NOT_SUPPORTED;
	}

	negotiate_request->uuid = it;
	it += UUID_SIZE;

	negotiate_request->remote_id = toxext_read_uint16(it) >> 3;
	it += 2;

	return TOXEXT_SUCCESS;
}

static void toxext_append_negotiate_response(uint16_t remote_id,
					     uint16_t local_id, bool compatible,
					     struct ToxExtPacketList *packet)
{
	uint8_t data[TOXEXT_NEGOTIATE_RESPONSE_SEGMENT_SIZE];
	toxext_write_uint16(data, remote_id << 3);
	data[1] |= ((local_id & 0xe0000) >> 13) & 0xff;
	data[2] = (local_id >> 2 & 0xff);
	data[3] = (local_id << 6) & 0xff;
	data[3] |= compatible << 5;

	int err = toxext_append_segment_to_packet_list(
		packet, TOXEXT_SEGMENT_NEGOTIATE_RESPONSE, data,
		TOXEXT_NEGOTIATE_RESPONSE_SEGMENT_SIZE);
	assert(err == 0);
	(void)err;
}

/**
 * Handles a negotiation packet. This packet is a request from a peer to
 * find out if we have a given extension
 */
static int
toxext_handle_negotiate_segment(struct ToxExt *toxext, uint32_t friend_id,
			       uint8_t const *data, size_t size,
			       struct ToxExtPacketList *output_packet_list)
{
	struct ToxExtNegotiateRequest request;
	int err = toxext_parse_negotiate_segment(data, size, &request);
	if (err != TOXEXT_SUCCESS) {
		return err;
	}

	struct ToxExtExtension *extension =
		toxext_uuid_to_extension(toxext, request.uuid);
	/* If we don't have the extension we have no work to do */
	if (!extension) {
		toxext_append_negotiate_response(request.remote_id, 0, false,
						 output_packet_list);

		return TOXEXT_SUCCESS;
	}

	/* Otherwise we have to update our own state */
	err = toxext_insert_connection(toxext, request.remote_id, extension,
				       friend_id);

	if (err != TOXEXT_SUCCESS) {
		return err;
	}

	toxext_append_negotiate_response(request.remote_id, extension->id, true,
					 output_packet_list);

	/* A negotiation request indicates that they do have the extension. Let our extension know */
	extension->negotiate_extension_cb(extension, friend_id, true,
					  extension->userdata, output_packet_list);

	return TOXEXT_SUCCESS;
}

struct ToxExtNegotiateResponse {
	uint16_t local_extension_id;
	bool remote_extension_exists;
	uint16_t remote_extension_id;
};

static int
toxext_parse_negotiate_response_segment(uint8_t const *data, size_t size,
				       struct ToxExtNegotiateResponse *response)
{
	if (size != TOXEXT_NEGOTIATE_RESPONSE_SEGMENT_SIZE) {
		return TOXEXT_INVALID_SEGMENT;
	}

	uint8_t const *it = data;

	/* The first piece is aligned on a byte boundary so we can re-use our uint 16 reader */
	response->local_extension_id = toxext_read_uint16(it) >> 3;

	response->remote_extension_id = 0;
	/* FIXME: We're gonna have to write some tests for big extension ids */
	response->remote_extension_id |= (data[1] & 0x7) << 13;
	response->remote_extension_id |= (data[2]) << 2;
	response->remote_extension_id |= (data[3] & 0xc0) >> 6;
	response->remote_extension_exists = (data[3] >> 5) & 0x1;

	return TOXEXT_SUCCESS;
}

static int toxext_handle_negotiate_response_segment(
	struct ToxExt *toxext, uint32_t friend_id, uint8_t const *data,
	size_t size, struct ToxExtPacketList *output_packet_list)
{
	struct ToxExtNegotiateResponse response;
	int err = toxext_parse_negotiate_response_segment(data, size, &response);
	if (err != TOXEXT_SUCCESS) {
		return err;
	}

	struct ToxExtExtension *extension =
		toxext_lookup_local_id(toxext, response.local_extension_id);
	if (!extension) {
		return TOXEXT_NOT_SUPPORTED;
	}

	if (!response.remote_extension_exists) {
		extension->negotiate_extension_cb(extension, friend_id, false,
						  extension->userdata, NULL);
		return TOXEXT_SUCCESS;
	}

	err = toxext_insert_connection(toxext, response.remote_extension_id,
				       extension, friend_id);

	if (err != TOXEXT_SUCCESS) {
		return err;
	}

	extension->negotiate_extension_cb(extension, friend_id, true,
					  extension->userdata, output_packet_list);

	return TOXEXT_SUCCESS;
}

static int toxext_handle_revoke_segment(struct ToxExt *toxext,
				       uint32_t friend_id, uint8_t const *data,
				       size_t size)
{
	if (size != 2) {
		return TOXEXT_INVALID_SEGMENT;
	}

	uint8_t const *it = data;
	uint16_t revoke_id = toxext_read_uint16(it) >> 3;

	struct ToxExtConnection *connection =
		toxext_id_to_connection(toxext, revoke_id, friend_id);

	if (!connection) {
		/* If we didn't even know they had the extension we have no work to do */
		return TOXEXT_SUCCESS;
	}

	/*
	 * Before we remove it lets tell our client that this friend doesn't support
	 * this extension anymore
	 */
	connection->extension->negotiate_extension_cb(
		connection->extension, friend_id, false,
		connection->extension->userdata, NULL);

	toxext_remove_connection(toxext, connection->connection_id,
				 connection->friend_id);

	return TOXEXT_SUCCESS;
}

/**
 * Each toxext packet list can have several extension's data associated with them.
 * This handles a single extension segment.
 */
static int toxext_handle_lossless_custom_packet_segment(
	struct ToxExt *toxext, enum ToxExtSegmentType segment_type,
	uint32_t friend_id, uint8_t const *data, size_t size,
	struct ToxExtPacketList *output_packet_list)
{
	switch (segment_type) {
	case TOXEXT_SEGMENT_NEGOTIATE: {
		return toxext_handle_negotiate_segment(toxext, friend_id, data,
						      size, output_packet_list);
	}
	case TOXEXT_SEGMENT_NEGOTIATE_RESPONSE: {
		return toxext_handle_negotiate_response_segment(
			toxext, friend_id, data, size, output_packet_list);
	}
	case TOXEXT_SEGMENT_REVOKE: {
		return toxext_handle_revoke_segment(toxext, friend_id, data,
						   size);
	}
	default: {
		/* Reuse the packet_type field as a connection_id */
		struct ToxExtConnection *connection =
			toxext_id_to_connection(toxext, segment_type, friend_id);

		if (connection) {
			struct ToxExtExtension *extension =
				connection->extension;
			extension->recv_cb(extension, friend_id, data, size,
					   extension->userdata, output_packet_list);
		} else {
			return TOXEXT_NOT_CONNECTED;
		}
		return TOXEXT_SUCCESS;
	}
	}
}

int toxext_handle_lossless_custom_packet(struct ToxExt *toxext,
					 uint32_t friend_id, void const *data_v,
					 size_t size)
{
	if (size < TOXEXT_MAGIC_SIZE + TOXEXT_SEGMENT_HEADER_SIZE) {
		return TOXEXT_INVALID_SEGMENT;
	}

	uint8_t const *const data = data_v;

	if (toxext_read_int32(data) != TOXEXT_MAGIC) {
		return TOXEXT_INVALID_SEGMENT;
	}

	uint8_t const *it = data + TOXEXT_MAGIC_SIZE;

	struct ToxExtPacketList *packet =
		toxext_packet_list_create(toxext, friend_id);
	while ((size_t)(it - data) < size) {
		if (size < TOXEXT_SEGMENT_HEADER_SIZE) {
			return TOXEXT_INVALID_SEGMENT;
		}
		uint16_t segment_type = toxext_read_segment_id(it);
		uint16_t segment_size = toxext_read_segment_size(it);
		it += TOXEXT_SEGMENT_HEADER_SIZE;
		int err = toxext_handle_lossless_custom_packet_segment(
			toxext, segment_type, friend_id, it, segment_size,
			packet);
		if (err != TOXEXT_SUCCESS)
			return err;
		it += segment_size;
	}

	toxext_send(packet);
	return TOXEXT_SUCCESS;
}

int toxext_negotiate_connection(struct ToxExtExtension *extension,
				uint32_t friend_id)
{
	uint8_t data[TOXEXT_NEGOTIATE_SEGMENT_SIZE];

	toxext_write_int32(data, TOXEXT_PROTOCOL_VERSION);
	memcpy(data + 4, extension->uuid, sizeof(extension->uuid));
	toxext_write_uint16(data + 20, extension->id << 3);

	struct ToxExtPacket packet;
	int err = toxext_init_packet_header(&packet);

	/* If we are not constructing a valid packet we've done soemthing very wrong */
	assert(err == 0);
	(void)err;

	err = toxext_append_segment_data_to_packet(&packet, TOXEXT_SEGMENT_NEGOTIATE,
					   data, sizeof(data));

	assert(err == 0);

	err = !tox_friend_send_lossless_packet(extension->toxext->tox,
					       friend_id, packet.buf,
					       packet.len, NULL);

	/**
	 * Error clobbering is kinda lame but our error types are different, we can
	 * propogate the toxcore error in an error* field later if we like
	 */
	if (err) {
		return TOXEXT_SEND_FAILED;
	}

	return TOXEXT_SUCCESS;
}

int toxext_revoke_connection(struct ToxExtExtension *extension,
			     uint32_t friend_id)
{
	struct ToxExt *toxext = extension->toxext;

	/* Move connection to then end of the list for easy mangagement */
	struct ToxExtExtensionAndFriendId ext_and_friend_id = {
		.extension = extension, .friend_id = friend_id
	};

	toxext_move_item_to_end(toxext->connections, toxext->num_connections,
				&ext_and_friend_id,
				connection_has_extension_and_friend_id);

	size_t connection_idx = toxext->num_connections - 1;
	struct ToxExtConnection *connection =
		&toxext->connections[connection_idx];

	if (connection->friend_id != friend_id) {
		return TOXEXT_DOES_NOT_EXIST;
	}

	/* Indicate to friend that we no longer support this extension */
	struct ToxExtPacket packet;
	int err = toxext_init_packet_header(&packet);
	assert(err == 0);
	(void)err;

	uint8_t data[2];
	toxext_write_uint16(data, connection->connection_id << 3);
	err = toxext_append_segment_data_to_packet(&packet, TOXEXT_SEGMENT_REVOKE,
					   data, sizeof(data));

	assert(err == 0);

	/*
	 * Ignore errors for now, if we can't talk to them they'll find out later that
	 * we don't accept them anymore
	 */
	tox_friend_send_lossless_packet(extension->toxext->tox, friend_id,
					packet.buf, packet.len, NULL);

	/* If we fail to realloc we can still just not use that item */
	toxext->num_connections--;
	/* Remove connection from list */
	struct ToxExtConnection *new_connections = new_connections = realloc(
		toxext->connections,
		toxext->num_connections * sizeof(struct ToxExtConnection));

	if (new_connections || toxext->num_connections == 0) {
		toxext->connections = new_connections;
	}

	return TOXEXT_SUCCESS;
}
