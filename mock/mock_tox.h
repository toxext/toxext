#pragma once

#include <tox/tox.h>

/**
 * Gets the globally used friend ID for the given tox instance
 */
uint32_t tox_get_id(Tox *tox);

/**
 * Sets the sendq size for the _receiver_ tox instance
 */
void tox_set_sendq_size(Tox *tox, size_t size);
