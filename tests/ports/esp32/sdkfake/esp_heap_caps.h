/* sdkfake esp_heap_caps.h — fixed heap figures for the console's readout. */
#ifndef SDKFAKE_ESP_HEAP_CAPS_H
#define SDKFAKE_ESP_HEAP_CAPS_H

#include <stddef.h>
#include <stdint.h>

#define MALLOC_CAP_INTERNAL (1 << 11)

static inline size_t heap_caps_get_free_size(uint32_t caps)
{
	(void)caps;
	return 65536;
}

static inline size_t heap_caps_get_largest_free_block(uint32_t caps)
{
	(void)caps;
	return 32768;
}

static inline size_t heap_caps_get_minimum_free_size(uint32_t caps)
{
	(void)caps;
	return 16384;
}

#endif
