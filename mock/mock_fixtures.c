#include "mock_fixtures.h"
#include "mock_tox.h"

static void
toxext_user_handle_tox_friend_lossless_packet(Tox *tox, uint32_t friend_number,
					      const uint8_t *data,
					      size_t length, void *user_data)
{
	(void)tox;

	struct ToxUser *user = user_data;
	struct ToxExtUser *toxext_user =
		container_of(user, struct ToxExtUser, tox_user);

	toxext_handle_lossless_custom_packet(toxext_user->toxext, friend_number,
					     data, length);
}

static void tox_user_handle_tox_friend_lossless_packet(Tox *tox,
						       uint32_t friend_number,
						       const uint8_t *data,
						       size_t length,
						       void *user_data)
{
	struct ToxUser *user = user_data;
	if (user->lossless_packet_cb)
		user->lossless_packet_cb(tox, friend_number, data, length,
					 user_data);
}

void toxext_test_init_tox_user(struct ToxUser *tox_user)
{
	tox_user->tox = tox_new(NULL, NULL);
	tox_user->id = tox_get_id(tox_user->tox);
	tox_user->lossless_packet_cb = NULL;
	tox_callback_friend_lossless_packet(
		tox_user->tox, tox_user_handle_tox_friend_lossless_packet);
}

void toxext_test_cleanup_tox_user(struct ToxUser *tox_user)
{
	tox_kill(tox_user->tox);
}

void toxext_test_init_tox_ext_user(struct ToxExtUser *toxext_user)
{
	toxext_test_init_tox_user(&toxext_user->tox_user);
	toxext_user->toxext = toxext_init(toxext_user->tox_user.tox);
	toxext_user->tox_user.lossless_packet_cb =
		toxext_user_handle_tox_friend_lossless_packet;
}

void toxext_test_cleanup_tox_ext_user(struct ToxExtUser *toxext_user)
{
	toxext_free(toxext_user->toxext);
	toxext_test_cleanup_tox_user(&toxext_user->tox_user);
}
