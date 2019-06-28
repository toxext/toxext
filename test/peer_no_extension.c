#include "mock_fixtures.h"
#include "mock_tox.h"
#include "toxext.h"

#include <tox/tox.h>

#include <assert.h>

static uint8_t my_extension_uuid[16] = { 0xdd };

struct NegotiateData {
	size_t num_negotiations;
	bool peer_compatible;
	uint32_t friend_id;
};

struct SingleExtensionUser {
	struct ToxExtUser toxext_user;
	struct ToxExtExtension *my_extension;
	struct NegotiateData negotiate_data;
};

void init_single_extension_user(
	struct SingleExtensionUser *single_extension_user)
{
	toxext_test_init_tox_ext_user(&single_extension_user->toxext_user);
	single_extension_user->negotiate_data.num_negotiations = 0;
	single_extension_user->negotiate_data.peer_compatible = false;
	single_extension_user->negotiate_data.friend_id = 0;
}

void cleanup_single_extension_user(
	struct SingleExtensionUser *single_extension_user)
{
	toxext_test_cleanup_tox_ext_user(&single_extension_user->toxext_user);
}

void my_extension_neg_callback(struct ToxExtExtension *extension,
			       uint32_t friend_id, bool compatible,
			       void *userdata, struct ToxExtPacketList *packet)
{
	(void)packet;

	struct SingleExtensionUser *extension_user = userdata;

	assert(extension_user->my_extension == extension);

	extension_user->negotiate_data.friend_id = friend_id;
	extension_user->negotiate_data.peer_compatible = compatible;
	extension_user->negotiate_data.num_negotiations++;
}

/*
 * Tests that when a peer has toxext, but does not have our extension that our
 * extension gets notified that they do not have our extension
 */
int main(void)
{
	struct SingleExtensionUser user_a;
	init_single_extension_user(&user_a);
	user_a.my_extension =
		toxext_register(user_a.toxext_user.toxext, my_extension_uuid,
				&user_a, NULL, my_extension_neg_callback);

	struct ToxExtUser user_b;
	toxext_test_init_tox_ext_user(&user_b);

	toxext_negotiate_connection(user_a.my_extension, user_b.tox_user.id);

	tox_iterate(user_b.tox_user.tox, &user_b.tox_user);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_a.toxext_user.tox_user);

	assert(user_a.negotiate_data.num_negotiations == 1);
	assert(user_a.negotiate_data.friend_id == user_b.tox_user.id);
	assert(user_a.negotiate_data.peer_compatible == false);

	toxext_test_cleanup_tox_ext_user(&user_b);
	cleanup_single_extension_user(&user_a);

	return 0;
}
