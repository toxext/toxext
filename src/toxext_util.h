#pragma once

/*
 * Writes size bytes of data to buffer, assumes buffer fits size bytes and
 * buffer holds single byte data
 */
// is this really public header stuff? defined as PUBLIC_HEADER in cmake

#define toxext_write_to_buf(data, buffer, size)                                \
	do {                                                                   \
		size_t __effective_size =                                      \
			(size > sizeof(data)) ? sizeof(data) : size;           \
		size_t __offset =                                              \
			(size > sizeof(data)) ? size - sizeof(data) : 0;       \
		memset(buffer, 0, __offset);                                   \
		for (size_t i = 0; i < __effective_size; ++i) {                \
			(buffer)[i + (__offset)] =                             \
				((data) >> ((__effective_size - i - 1) * 8)) & \
				0xff;                                          \
		}                                                              \
	} while (0)

/*
 * Reads size bytes from buffer into a variable of type type.
 * Assumes buffer holds single byte data and is >= size bytes
 */
#define toxext_read_from_buf(type, buffer, size)                               \
	({                                                                     \
		type __val = 0;                                                \
		size_t __effective_size =                                      \
			(size > sizeof(type)) ? sizeof(type) : size;           \
		for (size_t i = 0; i < __effective_size; ++i) {                \
			__val |= (buffer)[i]                                   \
				 << (__effective_size - i - 1) * 8;            \
		}                                                              \
		__val;                                                         \
	})
