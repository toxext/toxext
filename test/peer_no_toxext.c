#include "mock_fixtures.h"
#include "mock_tox.h"
#include "toxext.h"

#include <tox/tox.h>

#include <assert.h>
#include <stdio.h>

static uint8_t my_extension_uuid[16] = { 0xdd };

struct SingleExtensionUser {
	struct ToxExtUser toxext_user;
	struct ToxExtExtension *my_extension;
};

/*
 * Tests that when a peer does not have toxext we do not accidentally spuriously
 * fire notifications
 */
int main(void)
{
	struct SingleExtensionUser user_a;
	toxext_test_init_tox_ext_user(&user_a.toxext_user);

	/*
   * If user_b doesn't even have toxext we should just never get a callback from
   * them. This means we shouldn't get a negotiation callback from them.
   * If they try to call either of our callbacks we'll segfault and the test
   * will fail
   */
	user_a.my_extension =
		toxext_register(user_a.toxext_user.toxext, my_extension_uuid,
				&user_a, NULL, NULL);

	struct ToxUser user_b;
	toxext_test_init_tox_user(&user_b);

	toxext_negotiate_connection(user_a.my_extension, user_b.id);

	/* Make sure our userdata type is the same */
	tox_iterate(user_b.tox, &user_b);
	tox_iterate(user_a.toxext_user.tox_user.tox,
		    &user_a.toxext_user.tox_user);

	toxext_test_cleanup_tox_ext_user(&user_a.toxext_user);
	toxext_test_cleanup_tox_user(&user_b);

	return 0;
}
