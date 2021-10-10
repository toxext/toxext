#include "mock_fixtures.h"
#include "toxext.h"
#include "mock_tox.h"

#include "assert.h"

static uint8_t my_extension_uuid[16] = { 0xab, 0xcd };

static int num_received_messages = 0;

void my_ext_recv_callback(struct ToxExtExtension *extension, uint32_t friend_id,
			  void const *data_v, size_t size, void *userdata,
			  struct ToxExtPacketList *response_packet)
{
	(void)extension;
	(void)friend_id;
	(void)data_v;
	(void)size;
	(void)userdata;
	(void)response_packet;
	num_received_messages++;
}
void my_ext_neg_callback(struct ToxExtExtension *extension, uint32_t friend_id,
			 bool compatible, void *userdata,
			 struct ToxExtPacketList *packet)
{
	(void)extension;
	(void)friend_id;
	(void)userdata;
	(void)packet;
	(void)compatible;
}

/* Test behavior of deferred packets */
int main(void)
{
	struct ToxExtUser user_a;
	toxext_test_init_tox_ext_user(&user_a);
	struct ToxExtExtension *extension_a =
		toxext_register(user_a.toxext, my_extension_uuid, NULL,
				my_ext_recv_callback, my_ext_neg_callback);

	struct ToxExtUser user_b;
	toxext_test_init_tox_ext_user(&user_b);

	toxext_register(user_b.toxext, my_extension_uuid, NULL,
			my_ext_recv_callback, my_ext_neg_callback);

	toxext_negotiate_connection(extension_a, user_b.tox_user.id);

	/* Clear outstanding packets from negotiation */
	tox_iterate(user_a.tox_user.tox, &user_a.tox_user);
	tox_iterate(user_b.tox_user.tox, &user_b.tox_user);

	/* Ensure that multiple packets will be deferred */
	tox_set_sendq_size(user_b.tox_user.tox, 1);

	/* Queue up 100 packets */
	for (int i = 0; i < 100; ++i) {
		struct ToxExtPacketList *packet_list =
			toxext_packet_list_create(user_a.toxext,
						  user_b.tox_user.id);
		toxext_segment_append(packet_list, extension_a, NULL, 0);
		toxext_send(packet_list);
	}

    /* Fire through the deferred packets */
	for (int i = 0; i < 100; ++i) {
		toxext_iterate(user_a.toxext);
		tox_iterate(user_a.tox_user.tox, &user_a.tox_user);
		tox_iterate(user_b.tox_user.tox, &user_b.tox_user);
	}

    /* And check that we got them all */
	assert(num_received_messages == 100);

	toxext_test_cleanup_tox_ext_user(&user_a);
	toxext_test_cleanup_tox_ext_user(&user_b);

	return 0;
}
