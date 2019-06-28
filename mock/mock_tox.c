#include <tox/tox.h>
#include <stdlib.h>
#include <string.h>

static Tox **toxes = NULL;
size_t toxes_size = 0;

struct ToxCustomMessage {
	uint32_t friend_id;
	uint8_t *data;
	size_t length;
};

/* We will use this as an identifier for a single friend. */
struct Tox {
	uint32_t id;
	tox_friend_lossless_packet_cb *callback;
	struct ToxCustomMessage *incoming_messages;
	size_t incoming_messages_size;
	size_t max_messages_size;
};

static bool tox_push_message(Tox *tox, uint32_t friend_id, const uint8_t *data,
			     size_t length)
{
	if (tox->max_messages_size &&
	    tox->max_messages_size < tox->incoming_messages_size + 1) {
		goto fail;
	}

	struct ToxCustomMessage *new_messages =
		realloc(tox->incoming_messages,
			(tox->incoming_messages_size + 1) *
				sizeof(struct ToxCustomMessage));

	if (!new_messages)
		goto fail;

	tox->incoming_messages = new_messages;
	tox->incoming_messages_size++;

	struct ToxCustomMessage *new_message =
		&tox->incoming_messages[tox->incoming_messages_size - 1];
	new_message->data = malloc(length);

	if (!new_message->data)
		goto data_alloc_fail;

	memcpy(new_message->data, data, length);
	new_message->length = length;
	new_message->friend_id = friend_id;

	return true;

data_alloc_fail:
	tox->incoming_messages_size--;
fail:
	return false;
}

// Each call to tox_new gets a new "Tox" instance for a user
Tox *tox_new(const struct Tox_Options *options, TOX_ERR_NEW *error)
{
	(void)options;
	(void)error;

	Tox **new_toxes = realloc(toxes, (toxes_size + 1) * sizeof(Tox *));

	if (!new_toxes) {
		return NULL;
	}

	toxes = new_toxes;
	toxes_size += 1;

	size_t id = toxes_size - 1;

	/* FIXME handle failure */
	toxes[id] = malloc(sizeof(Tox));
	Tox *ret = toxes[id];

	ret->id = id;
	ret->callback = NULL;
	ret->incoming_messages = NULL;
	ret->incoming_messages_size = 0;
	ret->max_messages_size = 0;
	return ret;
}

void tox_kill(Tox *tox)
{
	for (size_t i = 0; i < tox->incoming_messages_size; ++i) {
		free(tox->incoming_messages[i].data);
	}
	free(tox->incoming_messages);
	free(tox);

	size_t toxidx;
	bool toxidx_found = false;
	for (size_t i = 0; i < toxes_size; ++i) {
		if (toxes[i] == tox) {
			toxidx = i;
			toxidx_found = true;
			break;
		}
	}

	if (!toxidx_found) {
		return;
	}

	toxes[toxidx] = toxes[toxes_size - 1];
	Tox **new_toxes = realloc(toxes, sizeof(Tox *) * (toxes_size - 1));

	if (!new_toxes)
		return;

	toxes = new_toxes;
	toxes_size--;
}

void tox_iterate(Tox *tox, void *user_data)
{
	for (size_t i = 0; i < tox->incoming_messages_size; ++i) {
		struct ToxCustomMessage *incoming_message =
			&tox->incoming_messages[i];

		tox->callback(tox, incoming_message->friend_id,
			      incoming_message->data, incoming_message->length,
			      user_data);

		free(incoming_message->data);
	}

	tox->incoming_messages_size = 0;
}

void tox_callback_friend_lossless_packet(
	Tox *tox, tox_friend_lossless_packet_cb *callback)
{
	tox->callback = callback;
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number,
				     const uint8_t *data, size_t length,
				     TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
	Tox *friend_tox = toxes[friend_number];
	uint32_t my_friend_number = tox->id;

	bool success =
		tox_push_message(friend_tox, my_friend_number, data, length);

	if (error) {
		*error = (success) ? TOX_ERR_FRIEND_CUSTOM_PACKET_OK :
				     TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ;
	}

	return success;
}

uint32_t tox_get_id(Tox *tox)
{
	return tox->id;
}

void tox_set_sendq_size(Tox *tox, size_t size)
{
	tox->max_messages_size = size;
}
