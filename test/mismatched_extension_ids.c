#include "mock_fixtures.h"
#include "mock_tox.h"
#include "toxext.h"

#include <tox/tox.h>

#include <assert.h>

static uint8_t a_uuid[16] = { 0x01 };
static uint8_t b_uuid[16] = { 0x00, 0x01 };

struct ExtensionData {
	int num_negotiations;
	bool compatible;
};

struct SingleExtensionUser {
	struct ToxExtUser toxext_user;
	struct ToxExtExtension *extension_a;
	struct ExtensionData extension_a_data;
};

struct DoubleExtensionUser {
	struct ToxExtUser toxext_user;
	struct ToxExtExtension *extension_a;
	struct ExtensionData extension_a_data;
	struct ToxExtExtension *extension_b;
	struct ExtensionData extension_b_data;
};

void extension_neg_callback(struct ToxExtExtension *extension,
			    uint32_t friend_id, bool compatible, void *userdata,
			    struct ToxExtPacketList *packet)
{
	struct ExtensionData *extension_data = userdata;
	(void)extension;
	(void)friend_id;
	(void)packet;
	extension_data->num_negotiations++;
	extension_data->compatible = compatible;
}

void init_extension_data(struct ExtensionData *extension_data)
{
	extension_data->num_negotiations = 0;
	extension_data->compatible = false;
}

/*
 * Tests that when we've registered in different orders for differnet clients we
 * still talk to eachother correctly. Internally the toxext protocol sets ids
 * for each extension that can be mismatched between clients. This test ensures
 * that we aren't ever accidentally using our own id instead of our peers when
 * we're supposed to
 */
int main(void)
{
	struct SingleExtensionUser user_a;
	init_extension_data(&user_a.extension_a_data);
	toxext_test_init_tox_ext_user(&user_a.toxext_user);
	user_a.extension_a = toxext_register(user_a.toxext_user.toxext, a_uuid,
					     &user_a.extension_a_data, NULL,
					     extension_neg_callback);

	struct DoubleExtensionUser user_b;
	toxext_test_init_tox_ext_user(&user_b.toxext_user);
	init_extension_data(&user_b.extension_a_data);
	init_extension_data(&user_b.extension_b_data);

	/* Register b first so that they're in a different order */
	user_b.extension_b = toxext_register(user_b.toxext_user.toxext, b_uuid,
					     &user_b.extension_b_data, NULL,
					     extension_neg_callback);
	user_b.extension_a = toxext_register(user_b.toxext_user.toxext, a_uuid,
					     &user_b.extension_a_data, NULL,
					     extension_neg_callback);

	toxext_negotiate_connection(user_a.extension_a,
				    user_b.toxext_user.tox_user.id);

	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_a.toxext_user.tox_user);
	tox_iterate(user_b.toxext_user.tox_user.tox,
		    &user_b.toxext_user.tox_user);

	/* user_a should have told user_b that they're compatible with extension a */
	assert(user_b.extension_a_data.num_negotiations == 1);
	assert(user_b.extension_a_data.compatible == true);

	/* user_b should have told user_a that they're compatible with extension a */
	assert(user_a.extension_a_data.num_negotiations == 1);
	assert(user_a.extension_a_data.compatible == true);

	/* No one should have tried to talk to user_b about extension b */
	assert(user_b.extension_b_data.num_negotiations == 0);

	toxext_test_cleanup_tox_ext_user(&user_a.toxext_user);
	toxext_test_cleanup_tox_ext_user(&user_b.toxext_user);
}
