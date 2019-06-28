#pragma once

#include <tox/tox.h>

#include "toxext.h"

/*
 * Copy paste of the linux kernel's container_of macro to allow for "subclassing" in our mocks
 */
#ifndef container_of
#define container_of(ptr, type, member)                                        \
	({                                                                     \
		const typeof(((type *)0)->member) *__mptr = (ptr);             \
		(type *)((char *)__mptr - offsetof(type, member));             \
	})
#endif

/*
 * Mock abstraction to model a tox user with no extension support
 */
struct ToxUser {
	Tox *tox;
	uint32_t id;
	tox_friend_lossless_packet_cb *lossless_packet_cb;
};

/*
 * Mock abstraction to model a tox user with extension support
 */
struct ToxExtUser {
	struct ToxUser tox_user;
	struct ToxExt *toxext;
};

/*
 * Initializes an empty ToxUser
 *
 * Note: If this abstraction is used the tox_user _must_ be passed to the tox_iterate call
 */
void toxext_test_init_tox_user(struct ToxUser *tox_user);
void toxext_test_cleanup_tox_user(struct ToxUser *tox_user);

/*
 * Initializes an empty ToxExtUser
 *
 * Note: If this abstraction is used toxext_user.tox_user _must_ be passed to the tox_iterate call
 */
void toxext_test_init_tox_ext_user(struct ToxExtUser *toxext_user);

void toxext_test_cleanup_tox_ext_user(struct ToxExtUser *toxext_user);
