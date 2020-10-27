#include "mock_fixtures.h"
#include "toxext.h"
#include "mock_tox.h"

#include <assert.h>
#include <string.h>

static uint8_t const my_extension_uuid[16] = {};
static uint8_t const buf_a[TOXEXT_MAX_SEGMENT_SIZE] = { 0x00, 0x01, 0x02, 0x03 };
static uint8_t const buf_b[TOXEXT_MAX_SEGMENT_SIZE] = { 0xff, 0xfe, 0xfd, 0xfc };
static uint8_t const buf_c[TOXEXT_MAX_SEGMENT_SIZE] = { 0xfe, 0xfe, 0xfd, 0xfc };
static uint8_t const buf_d[TOXEXT_MAX_SEGMENT_SIZE] = { 0xfd, 0xfe, 0xfd, 0xfc };

struct MyExtensionUser {
	struct ToxExtUser toxext_user;
	struct ToxExtExtension *extension_handle;
	uint8_t buf_a[TOXEXT_MAX_SEGMENT_SIZE];
	uint8_t buf_b[TOXEXT_MAX_SEGMENT_SIZE];
	uint8_t buf_c[TOXEXT_MAX_SEGMENT_SIZE];
	uint8_t buf_d[TOXEXT_MAX_SEGMENT_SIZE];
};

int my_extension_create_buf_request(struct ToxExtExtension *extension,
				    uint8_t const *data, size_t size,
				    struct ToxExtPacketList *packet)
{
	return toxext_segment_append(packet, extension, data, size);
}

void my_extension_recv_callback(struct ToxExtExtension *extension,
				uint32_t friend_id, void const *data_v,
				size_t size, void *userdata,
				struct ToxExtPacketList *response_packet)
{
	(void)extension;
	(void)friend_id;
	(void)response_packet;
	uint8_t const *data = data_v;
	struct MyExtensionUser *my_extension_user = userdata;

	uint8_t *output;
	switch (*data) {
	case 0x00:
		output = my_extension_user->buf_a;
		break;
	case 0xff:
		output = my_extension_user->buf_b;
		break;
	case 0xfe:
		output = my_extension_user->buf_c;
		break;
	case 0xfd:
		output = my_extension_user->buf_d;
		break;
	default:
		assert(false);
		return;
	}

	memcpy(output, data_v, size);
}

void my_extension_neg_callback(struct ToxExtExtension *extension,
			       uint32_t friend_id, bool compatible,
			       void *userdata, struct ToxExtPacketList *packet)
{
	assert(compatible);
	(void)extension;
	(void)friend_id;
	(void)userdata;
	(void)packet;
}

void init_my_extension_user(struct MyExtensionUser *my_extension_user)
{
	toxext_test_init_tox_ext_user(&my_extension_user->toxext_user);
	my_extension_user->extension_handle =
		toxext_register(my_extension_user->toxext_user.toxext,
				my_extension_uuid, my_extension_user,
				my_extension_recv_callback,
				my_extension_neg_callback);
}

/*
 * Tests that large buffers will be correctly split across multiple toxcore
 * packets
 */
int main(void)
{
	struct MyExtensionUser user_a;
	init_my_extension_user(&user_a);

	struct MyExtensionUser user_b;
	init_my_extension_user(&user_b);

	toxext_negotiate_connection(user_a.extension_handle,
				    user_b.toxext_user.tox_user.id);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);

	/* Limit sendq size to check behavior when buffer fills */
	tox_set_sendq_size(user_a.toxext_user.tox_user.tox, 2);
	tox_set_sendq_size(user_b.toxext_user.tox_user.tox, 2);

	struct ToxExtPacketList *packet = toxext_packet_list_create(
		user_a.toxext_user.toxext, user_b.toxext_user.tox_user.id);
	int err = my_extension_create_buf_request(
		user_a.extension_handle, buf_a, TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	err = my_extension_create_buf_request(user_a.extension_handle, buf_b,
					      TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	toxext_send(packet);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);

	/*
	 * With 2 big buffers we expect the message to fit within two packets, so no
	 * toxext_iterate should be sufficient
	 */
	assert(memcmp(user_b.buf_a, buf_a, TOXEXT_MAX_SEGMENT_SIZE) == 0);
	assert(memcmp(user_b.buf_b, buf_b, TOXEXT_MAX_SEGMENT_SIZE) == 0);

	/*
	 * Reset the buffers of user_b to ensure that the next tests are valid too
	 */
	memset(user_b.buf_a, 0, TOXEXT_MAX_SEGMENT_SIZE);
	memset(user_b.buf_b, 0, TOXEXT_MAX_SEGMENT_SIZE);
	memset(user_b.buf_c, 0, TOXEXT_MAX_SEGMENT_SIZE);
	memset(user_b.buf_d, 0, TOXEXT_MAX_SEGMENT_SIZE);

	packet = toxext_packet_list_create(user_a.toxext_user.toxext,
					   user_b.toxext_user.tox_user.id);
	err = my_extension_create_buf_request(user_a.extension_handle, buf_a,
					      TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	err = my_extension_create_buf_request(user_a.extension_handle, buf_b,
					      TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	err = my_extension_create_buf_request(user_a.extension_handle, buf_c,
					      TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	err = my_extension_create_buf_request(user_a.extension_handle, buf_d,
					      TOXEXT_MAX_SEGMENT_SIZE, packet);

	assert(err == TOXEXT_SUCCESS);

	toxext_send(packet);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);

	/* We expect buffers a and b to be complete here but c and d to require a toxext_iterate call */
	assert(memcmp(user_b.buf_a, buf_a, TOXEXT_MAX_SEGMENT_SIZE) == 0);
	assert(memcmp(user_b.buf_b, buf_b, TOXEXT_MAX_SEGMENT_SIZE) == 0);
	assert(memcmp(user_b.buf_c, buf_c, TOXEXT_MAX_SEGMENT_SIZE) != 0);
	assert(memcmp(user_b.buf_d, buf_d, TOXEXT_MAX_SEGMENT_SIZE) != 0);

	toxext_iterate(user_a.toxext_user.toxext);
	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);

	assert(memcmp(user_b.buf_c, buf_c, TOXEXT_MAX_SEGMENT_SIZE) == 0);
	assert(memcmp(user_b.buf_d, buf_d, TOXEXT_MAX_SEGMENT_SIZE) == 0);

	toxext_test_cleanup_tox_ext_user(&user_a.toxext_user);
	toxext_test_cleanup_tox_ext_user(&user_b.toxext_user);
}
