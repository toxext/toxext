#include "mock_fixtures.h"
#include "mock_tox.h"
#include "toxext.h"
#include <assert.h>
#include <stdio.h>
#include <tox/tox.h>

static uint8_t my_extension_uuid[16] = { 0xdd, 0xff };

enum MyExtensionMessages {
	my_extension_message_request,
	my_extension_message_response
};

/*
 * Usually extensions would create proper serialization methods but since we
 * know it's looping back to us we can just cast our data to structs
 */
struct MyExtensionRequest {
	int a;
	int b;
} __attribute__((packed));

struct MyExtensionResponse {
	int res;
} __attribute__((packed));

/* Simple extension that asks remote to add two numbers together */
struct MyExtension {
	struct ToxExtExtension *extension_handle;
	uint32_t request_user;
	struct MyExtensionRequest request;
	uint32_t response_user;
	struct MyExtensionResponse response;
};

struct MyExtensionUser {
	struct ToxExtUser toxext_user;
	struct MyExtension my_extension;
};

static int my_extension_create_add_request(struct MyExtension *my_extension,
					   struct ToxExtPacketList *packet,
					   int a, int b)
{
	uint8_t data[9];

	data[0] = my_extension_message_request;

	struct MyExtensionRequest *request =
		(struct MyExtensionRequest *)(data + 1);
	request->a = a;
	request->b = b;

	return toxext_segment_append(packet, my_extension->extension_handle,
				    data, 9);
};

void my_extension_recv_callback(struct ToxExtExtension *extension,
				uint32_t friend_id, void const *data_v,
				size_t size, void *userdata,
				struct ToxExtPacketList *response_packet)
{
	struct MyExtension *my_extension = userdata;

	uint8_t const *data = data_v;
	uint8_t const *it = data;

	enum MyExtensionMessages message_type = *it;
	it += 1;

	switch (message_type) {
	case my_extension_message_request: {
		assert(size == 9);

		struct MyExtensionRequest *request =
			(struct MyExtensionRequest *)it;
		my_extension->request = *request;
		my_extension->request_user = friend_id;

		uint8_t response_data[5];
		response_data[0] = my_extension_message_response;
		struct MyExtensionResponse *response =
			(struct MyExtensionResponse *)(response_data + 1);
		response->res = request->a + request->b;

		int err = toxext_segment_append(response_packet, extension,
					       response_data, 5);
		assert(err == 0);

		break;
	}
	case my_extension_message_response: {
		assert(size == 5);

		struct MyExtensionResponse *response =
			(struct MyExtensionResponse *)it;
		my_extension->response_user = friend_id;
		my_extension->response = *response;

		break;
	}
	}
}

void my_extension_neg_callback(struct ToxExtExtension *extension,
			       uint32_t friend_id, bool compatible,
			       void *userdata, struct ToxExtPacketList *packet)
{
	(void)extension;
	(void)friend_id;
	(void)userdata;
	(void)packet;

	/* Setup of test should ensure that both users support my extension */
	assert(compatible);
}

/* Test basic flow of a simple extension */
int main(void)
{
	struct MyExtensionUser user_a;
	toxext_test_init_tox_ext_user(&user_a.toxext_user);
	user_a.my_extension.extension_handle =
		toxext_register(user_a.toxext_user.toxext, my_extension_uuid,
				&user_a.my_extension,
				my_extension_recv_callback,
				my_extension_neg_callback);

	struct MyExtensionUser user_b;
	toxext_test_init_tox_ext_user(&user_b.toxext_user);
	user_b.my_extension.extension_handle =
		toxext_register(user_b.toxext_user.toxext, my_extension_uuid,
				&user_b.my_extension,
				my_extension_recv_callback,
				my_extension_neg_callback);

	toxext_negotiate_connection(user_a.my_extension.extension_handle,
				    user_b.toxext_user.tox_user.id);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_a.toxext_user.tox_user);

	struct ToxExtPacketList *packet = toxext_packet_list_create(
		user_a.toxext_user.toxext, user_b.toxext_user.tox_user.id);
	my_extension_create_add_request(&user_a.my_extension, packet, 3, 4);
	toxext_send(packet);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_a.toxext_user.tox_user);

	assert(user_b.my_extension.request.a == 3);
	assert(user_b.my_extension.request.b == 4);
	assert(user_b.my_extension.request_user ==
	       user_a.toxext_user.tox_user.id);
	assert(user_a.my_extension.response.res == 7);
	assert(user_a.my_extension.response_user ==
	       user_b.toxext_user.tox_user.id);

	toxext_test_cleanup_tox_ext_user(&user_a.toxext_user);
	toxext_test_cleanup_tox_ext_user(&user_b.toxext_user);

	return 0;
}
