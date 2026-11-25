/*
 * Copyright © 2026 Smoothtalk
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * Turtle Beach / ROCCAT Kone XP Air (wired 10f5:5015, 2.4 GHz dongle 10f5:5017).
 *
 * Protocol reverse engineered from USB captures of Swarm II and verified with
 * our own reads and a no-op write; see PROTOCOL.md in the kone-xp-air-re repo.
 *
 * Everything goes through 30-byte feature reports with ID 0x06 on the vendor
 * collection (usage page >= 0xff00) of USB interface 2:
 *
 *   06 <target> <cmd> <op> <len> <payload...>
 *
 *   target: 0x00 = the USB device itself (wired mouse), 0x01 = the mouse
 *           behind the dongle.
 *   op:     0x06 write, 0x07 read request, 0x08 reply (in the GET data).
 *
 * Settings (cmd 0x46, 78 bytes) and buttons (cmd 0x47, 125 bytes) are per
 * profile and move in 25-byte chunks. A chunk is selected with
 * "06 <tgt> <cmd> 06 02 <chunk> <profile>", then either written with
 * "06 <tgt> <cmd> 06 <len> <data>" or read with "06 <tgt> <cmd> 07" followed
 * by a GET. Both blocks end in a 16-bit little-endian sum of all bytes before
 * it. The active profile is cmd 0x45: payload <active> <profile count>.
 *
 * The device rejects a SET that follows the previous one too closely, so
 * every transfer is followed by a short sleep, and writes poll the 0x44
 * status report the way Swarm II does.
 */

#include "config.h"
#include <assert.h>
#include <errno.h>
#include <linux/input.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libudev.h>
#include <sys/file.h>

#include "libratbag-private.h"
#include "libratbag-hidraw.h"

#define KXA_PID_WIRED			0x5015
#define KXA_PID_DONGLE			0x5017

#define KXA_REPORT_ID			0x06
#define KXA_REPORT_SIZE			30
#define KXA_HEADER_SIZE			5
#define KXA_CHUNK_SIZE			25

#define KXA_TARGET_LOCAL		0x00
#define KXA_TARGET_WIRELESS		0x01

#define KXA_CMD_DONGLE			0x00	/* dongle itself, target 00 */
#define KXA_CMD_DEBOUNCE		0x43	/* device-wide, one 19-byte packet */
#define KXA_CMD_STATUS			0x44
#define KXA_CMD_PROFILE			0x45
#define KXA_CMD_SETTINGS		0x46
#define KXA_CMD_BUTTONS			0x47

#define KXA_OP_WRITE			0x06
#define KXA_OP_READ			0x07
#define KXA_OP_REPLY			0x08
#define KXA_OP_ATTACH			0x04	/* cmd 0x00: start forwarding to the mouse */
#define KXA_OP_NOT_FORWARDING		0x0c	/* dongle reply before KXA_OP_ATTACH */

#define KXA_NUM_PROFILES		5
#define KXA_NUM_DPI			5
#define KXA_NUM_BUTTONS			15
#define KXA_NUM_LEDS			1

#define KXA_DELAY_MS			50	/* between transfers; 0 ms was rejected */
#define KXA_WRITE_SETTLE_MS		120	/* Swarm waits this long before polling 0x44 */

/* Settings block (cmd 0x46) */
#define KXA_SETTINGS_SIZE		78
#define KXA_S_TYPE			0	/* 0x06 */
#define KXA_S_SIZE			1	/* 0x4e */
#define KXA_S_PROFILE			2
#define KXA_S_DPI_MASK			5
#define KXA_S_DPI_ACTIVE		6
#define KXA_S_DPI_TABLE			7	/* 5 x u16 LE */
#define KXA_S_ANGLE_SNAPPING		27	/* 00 off, 01 on */
#define KXA_S_REPORT_RATE		29
#define KXA_S_EFFECT			30
#define KXA_S_EFFECT_SPEED		31	/* 1 (slow) .. 8 (fast) */
#define KXA_S_BRIGHTNESS		32
#define KXA_S_COLOR_GROUPS		36	/* 8 groups of 5 bytes: <a> <b> R G B */
#define KXA_S_COLOR_GROUP_SIZE		5
#define KXA_S_USER_GROUP_FIRST		1	/* groups 1..5 carry the static colour */
#define KXA_S_USER_GROUP_LAST		5

/*
 * Effects (Swarm II names): 01 Fully Lit, 02 Blink, 03 Breathe, 04 Heartbeat,
 * 05 Photon, 09 AIMO, 0a Colorwave, 13 Battery Indication. libratbag can show
 * on / breathing / cycle; Colorwave is the one that cycles colours by itself.
 */
#define KXA_EFFECT_STATIC		0x01
#define KXA_EFFECT_BREATHING		0x03
#define KXA_EFFECT_CYCLE		0x0a	/* Colorwave */

#define KXA_SPEED_MIN			1
#define KXA_SPEED_MAX			8
#define KXA_SPEED_STEP_MS		500	/* speed 8 = 500 ms ... speed 1 = 4000 ms */

/* Debounce (cmd 0x43): 11 0d 00 <ms> <ms> 0a x12 <u16 LE sum of the 17 bytes> */
#define KXA_DEBOUNCE_SIZE		19
#define KXA_D_MS			3

/* Button block (cmd 0x47) */
#define KXA_BUTTONS_SIZE		125
#define KXA_B_TYPE			0	/* 0x07, but not always set on the device */
#define KXA_B_SIZE			1	/* 0x7d */
#define KXA_B_PROFILE			2
#define KXA_B_ENTRIES			3	/* 30 x 4 bytes: 15 primary, 15 Easy-Shift */
#define KXA_B_ENTRY_SIZE		4

/* Button entry: 00 <p1> <p2> <type> */
#define KXA_BTN_TYPE_STANDARD		0x01
#define KXA_BTN_TYPE_DPI		0x02
#define KXA_BTN_TYPE_MEDIA		0x03
#define KXA_BTN_TYPE_KEYS		0x04
#define KXA_BTN_TYPE_HOTKEY		0x06	/* p1 = HID usage, p2 = modifiers */
#define KXA_BTN_TYPE_PROFILES		0x08
#define KXA_BTN_TYPE_EASYSHIFT		0x0a

#define KXA_DPI_MIN			50
#define KXA_DPI_MAX			19000	/* product spec, not verified on the device */

static const unsigned int kxa_report_rates[] = { 125, 250, 500, 1000 };
static const unsigned int kxa_debounces[] = { 2, 3, 5, 8, 10 };	/* what Swarm II offers */

struct kxa_data {
	uint8_t target;
	uint8_t profile_count;
	uint8_t settings[KXA_NUM_PROFILES][KXA_SETTINGS_SIZE];
	uint8_t buttons[KXA_NUM_PROFILES][KXA_BUTTONS_SIZE];
	uint8_t debounce[KXA_DEBOUNCE_SIZE];
	bool has_debounce;
	unsigned int dpis[300];
	size_t ndpis;
};

struct kxa_button_mapping {
	uint8_t type;
	uint8_t code;
	struct ratbag_button_action action;
};

/*
 * <type> is Swarm's function category, <code> the 1-based position in that
 * category's list. Confirmed: standard 03/04/05/06/09/0a, DPI 01-03, keys
 * 01/04/07, media 04, profiles 01/02, hotkeys. Media 02/03/07/08 come from the
 * quick start guide's Easy-Shift defaults. The rest follows Swarm's list order
 * (likely).
 * Browser Back/Forward are mapped to buttons 4/5 like the other ROCCAT drivers.
 */
static const struct kxa_button_mapping kxa_button_map[] = {
	{ KXA_BTN_TYPE_STANDARD, 0x01, BUTTON_ACTION_BUTTON(1) },
	{ KXA_BTN_TYPE_STANDARD, 0x02, BUTTON_ACTION_BUTTON(2) },
	{ KXA_BTN_TYPE_STANDARD, 0x03, BUTTON_ACTION_BUTTON(3) },
	{ KXA_BTN_TYPE_STANDARD, 0x04, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_DOUBLECLICK) },
	{ KXA_BTN_TYPE_STANDARD, 0x05, BUTTON_ACTION_BUTTON(5) },
	{ KXA_BTN_TYPE_STANDARD, 0x06, BUTTON_ACTION_BUTTON(4) },
	{ KXA_BTN_TYPE_STANDARD, 0x07, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_WHEEL_LEFT) },
	{ KXA_BTN_TYPE_STANDARD, 0x08, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_WHEEL_RIGHT) },
	{ KXA_BTN_TYPE_STANDARD, 0x09, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_WHEEL_UP) },
	{ KXA_BTN_TYPE_STANDARD, 0x0a, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_WHEEL_DOWN) },
	{ KXA_BTN_TYPE_DPI, 0x01, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_CYCLE_UP) },
	{ KXA_BTN_TYPE_DPI, 0x02, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_UP) },
	{ KXA_BTN_TYPE_DPI, 0x03, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_RESOLUTION_DOWN) },
	{ KXA_BTN_TYPE_MEDIA, 0x02, BUTTON_ACTION_KEY(KEY_PREVIOUSSONG) },
	{ KXA_BTN_TYPE_MEDIA, 0x03, BUTTON_ACTION_KEY(KEY_NEXTSONG) },
	{ KXA_BTN_TYPE_MEDIA, 0x04, BUTTON_ACTION_KEY(KEY_PLAYPAUSE) },
	{ KXA_BTN_TYPE_MEDIA, 0x07, BUTTON_ACTION_KEY(KEY_VOLUMEUP) },
	{ KXA_BTN_TYPE_MEDIA, 0x08, BUTTON_ACTION_KEY(KEY_VOLUMEDOWN) },
	{ KXA_BTN_TYPE_KEYS, 0x01, BUTTON_ACTION_KEY(KEY_INSERT) },
	{ KXA_BTN_TYPE_KEYS, 0x02, BUTTON_ACTION_KEY(KEY_DELETE) },
	{ KXA_BTN_TYPE_KEYS, 0x03, BUTTON_ACTION_KEY(KEY_HOME) },
	{ KXA_BTN_TYPE_KEYS, 0x04, BUTTON_ACTION_KEY(KEY_END) },
	{ KXA_BTN_TYPE_KEYS, 0x05, BUTTON_ACTION_KEY(KEY_PAGEUP) },
	{ KXA_BTN_TYPE_KEYS, 0x06, BUTTON_ACTION_KEY(KEY_PAGEDOWN) },
	{ KXA_BTN_TYPE_KEYS, 0x07, BUTTON_ACTION_KEY(KEY_LEFTCTRL) },
	{ KXA_BTN_TYPE_KEYS, 0x08, BUTTON_ACTION_KEY(KEY_LEFTSHIFT) },
	{ KXA_BTN_TYPE_KEYS, 0x09, BUTTON_ACTION_KEY(KEY_LEFTALT) },
	{ KXA_BTN_TYPE_KEYS, 0x0a, BUTTON_ACTION_KEY(KEY_LEFTMETA) },
	{ KXA_BTN_TYPE_KEYS, 0x0b, BUTTON_ACTION_KEY(KEY_CAPSLOCK) },
	{ KXA_BTN_TYPE_PROFILES, 0x01, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_PROFILE_CYCLE_UP) },
	{ KXA_BTN_TYPE_PROFILES, 0x02, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_PROFILE_UP) },
	{ KXA_BTN_TYPE_PROFILES, 0x03, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_PROFILE_DOWN) },
	{ KXA_BTN_TYPE_EASYSHIFT, 0x01, BUTTON_ACTION_SPECIAL(RATBAG_BUTTON_ACTION_SPECIAL_SECOND_MODE) },
};

/* ---------------------------------------------------------------------- */
/* Transport                                                               */
/* ---------------------------------------------------------------------- */

static int
kxa_send(struct ratbag_device *device, uint8_t cmd, uint8_t op,
	 const uint8_t *payload, uint8_t len)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t buf[KXA_REPORT_SIZE] = { 0 };
	int rc;

	if (len > KXA_REPORT_SIZE - KXA_HEADER_SIZE)
		return -EINVAL;

	buf[0] = KXA_REPORT_ID;
	buf[1] = drv_data->target;
	buf[2] = cmd;
	buf[3] = op;
	buf[4] = len;
	if (len)
		memcpy(&buf[KXA_HEADER_SIZE], payload, len);

	log_buf_raw(device->ratbag, "kone-xp-air: set ", buf, sizeof(buf));
	rc = ratbag_hidraw_set_feature_report(device, KXA_REPORT_ID, buf, sizeof(buf));
	msleep(KXA_DELAY_MS);
	if (rc < 0)
		return rc;
	if (rc != (int)sizeof(buf))
		return -EIO;

	return 0;
}

/* Reads the reply to the last request for @cmd. Returns the payload length. */
static int
kxa_recv(struct ratbag_device *device, uint8_t cmd, uint8_t *payload, size_t max)
{
	uint8_t buf[KXA_REPORT_SIZE] = { 0 };
	int rc;
	uint8_t len;

	rc = ratbag_hidraw_get_feature_report(device, KXA_REPORT_ID, buf, sizeof(buf));
	msleep(KXA_DELAY_MS);
	if (rc < 0)
		return rc;
	log_buf_raw(device->ratbag, "kone-xp-air: get ", buf, sizeof(buf));
	if (rc != (int)sizeof(buf))
		return -EIO;

	if (buf[0] == KXA_REPORT_ID && buf[2] == cmd && buf[3] == KXA_OP_NOT_FORWARDING) {
		log_debug(device->ratbag,
			  "kone-xp-air: dongle isn't forwarding to the mouse (cmd 0x%02x)\n", cmd);
		return -ENOTCONN;
	}
	if (buf[0] != KXA_REPORT_ID || buf[2] != cmd || buf[3] != KXA_OP_REPLY) {
		log_error(device->ratbag,
			  "kone-xp-air: unexpected reply %02x %02x %02x %02x to cmd 0x%02x\n",
			  buf[0], buf[1], buf[2], buf[3], cmd);
		return -EIO;
	}

	/* bytes after <len> are left over from earlier replies */
	len = buf[4];
	if (len > KXA_REPORT_SIZE - KXA_HEADER_SIZE || (size_t)len > max)
		return -EIO;
	memcpy(payload, &buf[KXA_HEADER_SIZE], len);

	return len;
}

static int
kxa_poll_status(struct ratbag_device *device)
{
	uint8_t status[KXA_REPORT_SIZE];
	int rc;

	rc = kxa_send(device, KXA_CMD_STATUS, KXA_OP_READ, NULL, 0);
	if (rc)
		return rc;
	rc = kxa_recv(device, KXA_CMD_STATUS, status, sizeof(status));
	return rc < 0 ? rc : 0;
}

/* A write SET followed by the same settle time and 0x44 poll Swarm II uses. */
static int
kxa_send_write(struct ratbag_device *device, uint8_t cmd,
	       const uint8_t *payload, uint8_t len)
{
	int rc;

	rc = kxa_send(device, cmd, KXA_OP_WRITE, payload, len);
	if (rc)
		return rc;
	msleep(KXA_WRITE_SETTLE_MS - KXA_DELAY_MS);

	return kxa_poll_status(device);
}

static uint16_t
kxa_checksum(const uint8_t *buf, size_t size)
{
	uint16_t sum = 0;

	for (size_t i = 0; i + 2 < size; i++)
		sum += buf[i];

	return sum;
}

static bool
kxa_checksum_is_valid(const uint8_t *buf, size_t size)
{
	uint16_t given = buf[size - 2] | (buf[size - 1] << 8);

	return kxa_checksum(buf, size) == given;
}

static void
kxa_checksum_update(uint8_t *buf, size_t size)
{
	uint16_t sum = kxa_checksum(buf, size);

	buf[size - 2] = sum & 0xff;
	buf[size - 1] = sum >> 8;
}

static int
kxa_read_block(struct ratbag_device *device, uint8_t cmd, unsigned int profile,
	       uint8_t *block, size_t size)
{
	size_t offset = 0;
	uint8_t chunk = 0;
	int rc;

	while (offset < size) {
		uint8_t select[2] = { chunk, profile };
		size_t want = size - offset;

		if (want > KXA_CHUNK_SIZE)
			want = KXA_CHUNK_SIZE;

		rc = kxa_send(device, cmd, KXA_OP_WRITE, select, sizeof(select));
		if (rc)
			return rc;
		rc = kxa_send(device, cmd, KXA_OP_READ, NULL, 0);
		if (rc)
			return rc;
		rc = kxa_recv(device, cmd, &block[offset], want);
		if (rc < 0)
			return rc;
		if ((size_t)rc != want)
			return -EIO;

		offset += want;
		chunk++;
	}

	if (!kxa_checksum_is_valid(block, size)) {
		log_error(device->ratbag,
			  "kone-xp-air: bad checksum in block 0x%02x of profile %u\n",
			  cmd, profile);
		return -EIO;
	}

	return 0;
}

static int
kxa_write_block(struct ratbag_device *device, uint8_t cmd, unsigned int profile,
		uint8_t *block, size_t size)
{
	size_t offset = 0;
	uint8_t chunk = 0;
	int rc;

	kxa_checksum_update(block, size);

	while (offset < size) {
		uint8_t select[2] = { chunk, profile };
		size_t len = size - offset;

		if (len > KXA_CHUNK_SIZE)
			len = KXA_CHUNK_SIZE;

		rc = kxa_send_write(device, cmd, select, sizeof(select));
		if (rc)
			return rc;
		rc = kxa_send_write(device, cmd, &block[offset], len);
		if (rc)
			return rc;

		offset += len;
		chunk++;
	}

	return 0;
}

/*
 * A freshly plugged dongle answers every mouse command with op 0x0c until the
 * host sends cmd 0x00 op 0x04 to the dongle itself (target 00). Swarm II sends
 * this first after every replug; its reply is empty (06 00 00 08 00 ...).
 */
static int
kxa_dongle_attach(struct ratbag_device *device)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t target = drv_data->target;
	uint8_t reply[KXA_REPORT_SIZE];
	int rc;

	drv_data->target = KXA_TARGET_LOCAL;
	rc = kxa_send(device, KXA_CMD_DONGLE, KXA_OP_ATTACH, NULL, 0);
	if (rc == 0)
		rc = kxa_recv(device, KXA_CMD_DONGLE, reply, sizeof(reply));
	drv_data->target = target;

	return rc < 0 ? rc : 0;
}

static int
kxa_read_active_profile(struct ratbag_device *device)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t payload[KXA_REPORT_SIZE];
	int rc;

	rc = kxa_send(device, KXA_CMD_PROFILE, KXA_OP_READ, NULL, 0);
	if (rc)
		return rc;
	rc = kxa_recv(device, KXA_CMD_PROFILE, payload, sizeof(payload));
	if (rc < 0)
		return rc;
	if (rc < 2)
		return -EIO;

	drv_data->profile_count = payload[1];

	return payload[0];
}

static int
kxa_read_debounce(struct ratbag_device *device)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t payload[KXA_REPORT_SIZE];
	int rc;

	rc = kxa_send(device, KXA_CMD_DEBOUNCE, KXA_OP_READ, NULL, 0);
	if (rc)
		return rc;
	rc = kxa_recv(device, KXA_CMD_DEBOUNCE, payload, sizeof(payload));
	if (rc < 0)
		return rc;
	if (rc != KXA_DEBOUNCE_SIZE || payload[0] != 0x11 || payload[1] != 0x0d ||
	    !kxa_checksum_is_valid(payload, KXA_DEBOUNCE_SIZE))
		return -EIO;

	memcpy(drv_data->debounce, payload, KXA_DEBOUNCE_SIZE);
	drv_data->has_debounce = true;

	return 0;
}

/*
 * The mouse ignores the trailing sum it is sent and stores its own (Swarm II
 * sends junk there), but we send the correct one anyway.
 */
static int
kxa_write_debounce(struct ratbag_device *device, unsigned int ms)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t payload[KXA_DEBOUNCE_SIZE];

	memcpy(payload, drv_data->debounce, sizeof(payload));
	payload[KXA_D_MS] = ms;
	payload[KXA_D_MS + 1] = ms;
	kxa_checksum_update(payload, sizeof(payload));

	return kxa_send_write(device, KXA_CMD_DEBOUNCE, payload, sizeof(payload));
}

/* ---------------------------------------------------------------------- */
/* Settings <-> libratbag                                                  */
/* ---------------------------------------------------------------------- */

static unsigned int
kxa_get_u16(const uint8_t *p)
{
	return p[0] | (p[1] << 8);
}

static void
kxa_set_u16(uint8_t *p, unsigned int v)
{
	p[0] = v & 0xff;
	p[1] = (v >> 8) & 0xff;
}

static uint8_t *
kxa_color_group(uint8_t *settings, unsigned int group)
{
	return &settings[KXA_S_COLOR_GROUPS + group * KXA_S_COLOR_GROUP_SIZE];
}

static void
kxa_parse_settings(struct ratbag_profile *profile)
{
	struct ratbag_device *device = profile->device;
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t *s = drv_data->settings[profile->index];
	struct ratbag_resolution *resolution;
	struct ratbag_led *led;
	uint8_t *group;

	ratbag_profile_set_report_rate_list(profile, kxa_report_rates,
					    ARRAY_LENGTH(kxa_report_rates));
	if ((size_t)s[KXA_S_REPORT_RATE] < ARRAY_LENGTH(kxa_report_rates))
		profile->hz = kxa_report_rates[s[KXA_S_REPORT_RATE]];
	else
		log_error(device->ratbag, "kone-xp-air: unknown report rate index %u\n",
			  s[KXA_S_REPORT_RATE]);

	ratbag_profile_for_each_resolution(profile, resolution) {
		unsigned int dpi = kxa_get_u16(&s[KXA_S_DPI_TABLE + 2 * resolution->index]);

		ratbag_resolution_set_resolution(resolution, dpi, dpi);
		ratbag_resolution_set_dpi_list(resolution, drv_data->dpis, drv_data->ndpis);
		ratbag_resolution_set_cap(resolution, RATBAG_RESOLUTION_CAP_DISABLE);
		resolution->is_disabled = !(s[KXA_S_DPI_MASK] & (1 << resolution->index));
		resolution->is_active = (resolution->index == (unsigned int)s[KXA_S_DPI_ACTIVE]);
	}

	if (s[KXA_S_ANGLE_SNAPPING] <= 1)
		profile->angle_snapping = s[KXA_S_ANGLE_SNAPPING];
	else
		log_debug(device->ratbag, "kone-xp-air: unknown angle snapping value %u\n",
			  s[KXA_S_ANGLE_SNAPPING]);

	/* debounce is device-wide; libratbag keeps it per profile, so mirror it */
	if (drv_data->has_debounce) {
		ratbag_profile_set_debounce_list(profile, kxa_debounces,
						 ARRAY_LENGTH(kxa_debounces));
		profile->debounce = drv_data->debounce[KXA_D_MS];
	}

	/*
	 * One logical LED: the five user colour groups always carry the same
	 * colour in Swarm II. Effect 0x0a (Colorwave) makes the mouse run a
	 * rainbow cycle on its own, so it is shown as "cycle". The other effects
	 * (blink, heartbeat, photon, AIMO, battery) are shown as "on" and left
	 * untouched unless the LED is changed.
	 */
	group = kxa_color_group(s, KXA_S_USER_GROUP_FIRST);
	ratbag_profile_for_each_led(profile, led) {
		led->colordepth = RATBAG_LED_COLORDEPTH_RGB_888;
		ratbag_led_set_mode_capability(led, RATBAG_LED_OFF);
		ratbag_led_set_mode_capability(led, RATBAG_LED_ON);
		ratbag_led_set_mode_capability(led, RATBAG_LED_BREATHING);
		ratbag_led_set_mode_capability(led, RATBAG_LED_CYCLE);

		led->color.red = group[2];
		led->color.green = group[3];
		led->color.blue = group[4];
		led->brightness = s[KXA_S_BRIGHTNESS];
		if (s[KXA_S_EFFECT_SPEED] >= KXA_SPEED_MIN && s[KXA_S_EFFECT_SPEED] <= KXA_SPEED_MAX)
			led->ms = (KXA_SPEED_MAX + 1 - s[KXA_S_EFFECT_SPEED]) * KXA_SPEED_STEP_MS;

		if (s[KXA_S_BRIGHTNESS] == 0)
			led->mode = RATBAG_LED_OFF;
		else if (s[KXA_S_EFFECT] == KXA_EFFECT_BREATHING)
			led->mode = RATBAG_LED_BREATHING;
		else if (s[KXA_S_EFFECT] == KXA_EFFECT_CYCLE)
			led->mode = RATBAG_LED_CYCLE;
		else
			led->mode = RATBAG_LED_ON;
	}
}

static int
kxa_apply_settings(struct ratbag_profile *profile)
{
	struct ratbag_device *device = profile->device;
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t *s = drv_data->settings[profile->index];
	struct ratbag_resolution *resolution;
	struct ratbag_led *led;
	uint8_t mask = 0;
	int active = -1;
	size_t i;

	for (i = 0; i < ARRAY_LENGTH(kxa_report_rates); i++) {
		if (kxa_report_rates[i] == profile->hz)
			break;
	}
	if (i == ARRAY_LENGTH(kxa_report_rates)) {
		log_error(device->ratbag, "kone-xp-air: unsupported report rate %u\n",
			  profile->hz);
		return -EINVAL;
	}
	s[KXA_S_REPORT_RATE] = i;

	ratbag_profile_for_each_resolution(profile, resolution) {
		unsigned int dpi = resolution->dpi_x;

		if (dpi < KXA_DPI_MIN || dpi > KXA_DPI_MAX || dpi % 50) {
			log_error(device->ratbag, "kone-xp-air: unsupported dpi %u\n", dpi);
			return -EINVAL;
		}
		kxa_set_u16(&s[KXA_S_DPI_TABLE + 2 * resolution->index], dpi);

		if (!resolution->is_disabled)
			mask |= 1 << resolution->index;
		if (resolution->is_active)
			active = resolution->index;
	}
	if (!mask || active < 0 || !(mask & (1 << active))) {
		log_error(device->ratbag,
			  "kone-xp-air: need an enabled, active resolution\n");
		return -EINVAL;
	}
	s[KXA_S_DPI_MASK] = mask;
	s[KXA_S_DPI_ACTIVE] = active;

	if (profile->angle_snapping_dirty)
		s[KXA_S_ANGLE_SNAPPING] = profile->angle_snapping ? 1 : 0;

	ratbag_profile_for_each_led(profile, led) {
		unsigned int brightness;

		if (!led->dirty)
			continue;

		switch (led->mode) {
		case RATBAG_LED_OFF:
			/* Swarm II has no "off"; brightness 0 is how it turns LEDs off */
			s[KXA_S_BRIGHTNESS] = 0;
			continue;
		case RATBAG_LED_ON:
			s[KXA_S_EFFECT] = KXA_EFFECT_STATIC;
			break;
		case RATBAG_LED_BREATHING:
			s[KXA_S_EFFECT] = KXA_EFFECT_BREATHING;
			break;
		case RATBAG_LED_CYCLE:
			s[KXA_S_EFFECT] = KXA_EFFECT_CYCLE;
			break;
		default:
			return -EINVAL;
		}

		/*
		 * Brightness is byte 32 in every effect, linear 0-255, and 00 turns
		 * the LEDs off (Swarm II writes 00 at the bottom of its slider in
		 * Fully Lit, Breathe and Colorwave). Write it as given, 0 included.
		 * The one exception is switching on from "off": the stored value is
		 * then 00, so use full brightness or the LED would stay dark.
		 */
		if (led->brightness > 255)
			brightness = 255;
		else
			brightness = led->brightness;
		if (brightness == 0 && s[KXA_S_BRIGHTNESS] == 0)
			brightness = 255;
		s[KXA_S_BRIGHTNESS] = brightness;

		/* duration -> Swarm's 8-step speed slider; 0 keeps the stored speed */
		if ((led->mode == RATBAG_LED_BREATHING || led->mode == RATBAG_LED_CYCLE) && led->ms) {
			int speed = KXA_SPEED_MAX + 1 -
				    (int)((led->ms + KXA_SPEED_STEP_MS / 2) / KXA_SPEED_STEP_MS);

			if (speed < KXA_SPEED_MIN)
				speed = KXA_SPEED_MIN;
			if (speed > KXA_SPEED_MAX)
				speed = KXA_SPEED_MAX;
			s[KXA_S_EFFECT_SPEED] = speed;
		}

		/* the cycle picks its own colours; keep the groups as they are */
		if (led->mode == RATBAG_LED_CYCLE)
			continue;

		for (unsigned int g = KXA_S_USER_GROUP_FIRST; g <= KXA_S_USER_GROUP_LAST; g++) {
			uint8_t *group = kxa_color_group(s, g);

			group[2] = led->color.red;
			group[3] = led->color.green;
			group[4] = led->color.blue;
		}
	}

	return 0;
}

/* ---------------------------------------------------------------------- */
/* Buttons <-> libratbag                                                   */
/* ---------------------------------------------------------------------- */

static uint8_t *
kxa_button_entry(struct kxa_data *drv_data, unsigned int profile, unsigned int button)
{
	return &drv_data->buttons[profile][KXA_B_ENTRIES + button * KXA_B_ENTRY_SIZE];
}

static void
kxa_parse_button(struct ratbag_button *button)
{
	struct ratbag_device *device = button->profile->device;
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	const uint8_t *e = kxa_button_entry(drv_data, button->profile->index, button->index);
	struct ratbag_button_action action = BUTTON_ACTION_UNKNOWN;
	const struct kxa_button_mapping *m;

	ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_NONE);
	ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_BUTTON);
	ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_SPECIAL);
	ratbag_button_enable_action_type(button, RATBAG_BUTTON_ACTION_TYPE_KEY);

	if (!e[0] && !e[1] && !e[2] && !e[3]) {
		struct ratbag_button_action none = BUTTON_ACTION_NONE;

		action = none;
	} else if (e[3] == KXA_BTN_TYPE_HOTKEY) {
		/* key with modifiers can't be represented; left as unknown */
		if (e[2] == 0) {
			unsigned int key = ratbag_hidraw_get_keycode_from_keyboard_usage(device, e[1]);

			if (key) {
				action.type = RATBAG_BUTTON_ACTION_TYPE_KEY;
				action.action.key = key;
			}
		}
	} else if (e[1] == 0) {
		ARRAY_FOR_EACH(kxa_button_map, m) {
			if (m->type == e[3] && m->code == e[2]) {
				action = m->action;
				break;
			}
		}
	}

	if (action.type == RATBAG_BUTTON_ACTION_TYPE_UNKNOWN)
		log_debug(device->ratbag,
			  "kone-xp-air: profile %u button %u has unknown function %02x %02x %02x %02x\n",
			  button->profile->index, button->index, e[0], e[1], e[2], e[3]);

	ratbag_button_set_action(button, &action);
}

static int
kxa_encode_button(struct ratbag_button *button)
{
	struct ratbag_device *device = button->profile->device;
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t *e = kxa_button_entry(drv_data, button->profile->index, button->index);
	const struct ratbag_button_action *action = &button->action;
	const struct kxa_button_mapping *m;

	switch (action->type) {
	case RATBAG_BUTTON_ACTION_TYPE_NONE:
		memset(e, 0, KXA_B_ENTRY_SIZE);
		return 0;
	case RATBAG_BUTTON_ACTION_TYPE_KEY: {
		uint8_t usage;

		/* keys Swarm has its own entry for (Insert, Ctrl, ...) use type 04 */
		ARRAY_FOR_EACH(kxa_button_map, m) {
			if (ratbag_button_action_match(&m->action, action)) {
				e[0] = 0;
				e[1] = 0;
				e[2] = m->code;
				e[3] = m->type;
				return 0;
			}
		}

		usage = ratbag_hidraw_get_keyboard_usage_from_keycode(device, action->action.key);
		if (!usage)
			return -EINVAL;
		e[0] = 0;
		e[1] = usage;
		e[2] = 0;
		e[3] = KXA_BTN_TYPE_HOTKEY;
		return 0;
	}
	case RATBAG_BUTTON_ACTION_TYPE_BUTTON:
	case RATBAG_BUTTON_ACTION_TYPE_SPECIAL:
		ARRAY_FOR_EACH(kxa_button_map, m) {
			if (ratbag_button_action_match(&m->action, action)) {
				e[0] = 0;
				e[1] = 0;
				e[2] = m->code;
				e[3] = m->type;
				return 0;
			}
		}
		return -EINVAL;
	default:
		return -EINVAL;
	}
}

/* ---------------------------------------------------------------------- */
/* Driver hooks                                                            */
/* ---------------------------------------------------------------------- */

/*
 * The mouse has one reply buffer, so two programs talking to it at once get
 * each other's replies. Other tools (e.g. kone-xp-air-re's battery script)
 * take an exclusive flock() on the same hidraw node around their packets; we
 * hold it for each whole transaction (probe, commit, profile switch). If
 * someone keeps it for more than 2 s, go ahead without it rather than hang.
 */
#define KXA_LOCK_TIMEOUT_MS		2000

static void
kxa_lock(struct ratbag_device *device)
{
	int fd = device->hidraw[0].fd;

	for (int waited = 0; waited < KXA_LOCK_TIMEOUT_MS; waited += 20) {
		if (flock(fd, LOCK_EX | LOCK_NB) == 0)
			return;
		if (errno != EWOULDBLOCK && errno != EINTR)
			break;
		msleep(20);
	}
	log_debug(device->ratbag, "kone-xp-air: couldn't lock the hidraw node, continuing\n");
}

static void
kxa_unlock(struct ratbag_device *device)
{
	flock(device->hidraw[0].fd, LOCK_UN);
}

static int
kxa_test_hidraw(struct ratbag_device *device)
{
	/*
	 * Interface 2's vendor collection (usage page 0xff03) owns feature
	 * report 0x06; that is the one Swarm II talks to. Interface 0 also
	 * declares a 29-byte vendor feature report 0x06 (page 0xff00) inside
	 * the mouse collection. Windows hides it, Linux hidraw does not.
	 * Accept only pages above 0xff00 so exactly one interface matches.
	 */
	return ratbag_hidraw_has_report(device, KXA_REPORT_ID) &&
	       ratbag_hidraw_get_usage_page(device, KXA_REPORT_ID) > 0xff00;
}

static void
kxa_build_dpi_list(struct kxa_data *drv_data)
{
	unsigned int dpi;

	/* the device stores any multiple of 50 (350 and 2100 were seen) */
	drv_data->ndpis = 0;
	for (dpi = KXA_DPI_MIN; dpi <= 5000; dpi += 50)
		drv_data->dpis[drv_data->ndpis++] = dpi;
	for (dpi = 5100; dpi <= KXA_DPI_MAX; dpi += 100)
		drv_data->dpis[drv_data->ndpis++] = dpi;
	assert(drv_data->ndpis <= ARRAY_LENGTH(drv_data->dpis));
}

/* Swarm II shows the USB bcdDevice as the version: 0x0113 -> "1.13", 0x0003 -> "0.3" */
static void
kxa_set_firmware_version(struct ratbag_device *device)
{
	struct udev_device *usb;
	const char *bcd;
	unsigned int v;
	char fw[16];

	usb = udev_device_get_parent_with_subsystem_devtype(device->udev_device, "usb", "usb_device");
	if (!usb)
		return;
	bcd = udev_device_get_sysattr_value(usb, "bcdDevice");
	if (!bcd || sscanf(bcd, "%x", &v) != 1)
		return;

	snprintf(fw, sizeof(fw), "%x.%x", (v >> 8) & 0xff, v & 0xff);
	ratbag_device_set_firmware_version(device, fw);
}

static int
kxa_probe(struct ratbag_device *device)
{
	struct kxa_data *drv_data;
	struct ratbag_profile *profile;
	struct ratbag_button *button;
	int active;
	int rc;

	switch (device->ids.product) {
	case KXA_PID_WIRED:
	case KXA_PID_DONGLE:
		break;
	default:
		return -ENODEV;
	}

	/*
	 * ratbagd creates one ratbag device per hidraw node, so only claim
	 * the mouse from the node that is itself the protocol interface.
	 * ratbag_find_hidraw() would search all sibling interfaces and let
	 * every node of the dongle claim it, listing the mouse several times.
	 */
	rc = ratbag_open_hidraw(device);
	if (rc)
		return rc;
	if (!kxa_test_hidraw(device)) {
		ratbag_close_hidraw(device);
		return -ENODEV;
	}

	kxa_lock(device);

	drv_data = zalloc(sizeof(*drv_data));
	drv_data->target = device->ids.product == KXA_PID_DONGLE ?
			   KXA_TARGET_WIRELESS : KXA_TARGET_LOCAL;
	kxa_build_dpi_list(drv_data);
	ratbag_set_drv_data(device, drv_data);

	if (device->ids.product == KXA_PID_DONGLE) {
		rc = kxa_dongle_attach(device);
		if (rc)
			log_error(device->ratbag, "kone-xp-air: dongle attach failed: %s\n",
				  strerror(-rc));
	}

	active = kxa_read_active_profile(device);
	if (active < 0) {
		log_error(device->ratbag,
			  "kone-xp-air: can't talk to the mouse (asleep or out of range?): %s\n",
			  strerror(-active));
		rc = -ENODEV;
		goto err;
	}
	if (drv_data->profile_count != KXA_NUM_PROFILES)
		log_debug(device->ratbag, "kone-xp-air: device reports %u profiles\n",
			  drv_data->profile_count);
	if (active >= KXA_NUM_PROFILES) {
		/* libratbag needs exactly one active profile */
		log_error(device->ratbag, "kone-xp-air: active profile %d out of range, using 0\n",
			  active);
		active = 0;
	}

	rc = kxa_read_debounce(device);
	if (rc)
		log_debug(device->ratbag, "kone-xp-air: can't read debounce (%s), not offering it\n",
			  strerror(-rc));

	kxa_set_firmware_version(device);

	ratbag_device_init_profiles(device, KXA_NUM_PROFILES, KXA_NUM_DPI,
				    KXA_NUM_BUTTONS, KXA_NUM_LEDS);

	ratbag_device_for_each_profile(device, profile) {
		rc = kxa_read_block(device, KXA_CMD_SETTINGS, profile->index,
				    drv_data->settings[profile->index], KXA_SETTINGS_SIZE);
		if (rc)
			goto err;
		rc = kxa_read_block(device, KXA_CMD_BUTTONS, profile->index,
				    drv_data->buttons[profile->index], KXA_BUTTONS_SIZE);
		if (rc)
			goto err;

		kxa_parse_settings(profile);
		ratbag_profile_for_each_button(profile, button)
			kxa_parse_button(button);

		profile->is_active = (profile->index == (unsigned int)active);
	}

	kxa_unlock(device);
	return 0;

err:
	kxa_unlock(device);
	ratbag_close_hidraw(device);
	free(drv_data);
	ratbag_set_drv_data(device, NULL);
	return rc;
}

static int
kxa_commit_locked(struct ratbag_device *device)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	struct ratbag_profile *profile;
	struct ratbag_resolution *resolution;
	struct ratbag_button *button;
	struct ratbag_led *led;
	int rc;

	/* debounce is device-wide: write it once, then mirror it into every profile */
	ratbag_device_for_each_profile(device, profile) {
		struct ratbag_profile *other;

		if (!profile->debounce_dirty || !drv_data->has_debounce)
			continue;

		if (profile->debounce <= 0 || profile->debounce > 0xff) {
			log_error(device->ratbag, "kone-xp-air: unsupported debounce %d ms\n",
				  profile->debounce);
			return -EINVAL;
		}
		rc = kxa_write_debounce(device, profile->debounce);
		if (rc)
			return rc;
		drv_data->debounce[KXA_D_MS] = profile->debounce;
		drv_data->debounce[KXA_D_MS + 1] = profile->debounce;
		kxa_checksum_update(drv_data->debounce, KXA_DEBOUNCE_SIZE);

		ratbag_device_for_each_profile(device, other) {
			other->debounce = profile->debounce;
			other->debounce_dirty = false;
		}
		break;
	}

	ratbag_device_for_each_profile(device, profile) {
		bool settings_dirty = profile->rate_dirty || profile->angle_snapping_dirty;
		bool buttons_dirty = false;
		uint8_t *b = drv_data->buttons[profile->index];

		if (!profile->dirty)
			continue;

		ratbag_profile_for_each_resolution(profile, resolution)
			settings_dirty |= resolution->dirty;
		ratbag_profile_for_each_led(profile, led)
			settings_dirty |= led->dirty;
		ratbag_profile_for_each_button(profile, button)
			buttons_dirty |= button->dirty;

		if (settings_dirty) {
			rc = kxa_apply_settings(profile);
			if (rc)
				return rc;
			rc = kxa_write_block(device, KXA_CMD_SETTINGS, profile->index,
					     drv_data->settings[profile->index],
					     KXA_SETTINGS_SIZE);
			if (rc)
				return rc;
		}

		if (buttons_dirty) {
			ratbag_profile_for_each_button(profile, button) {
				if (!button->dirty)
					continue;
				rc = kxa_encode_button(button);
				if (rc) {
					log_error(device->ratbag,
						  "kone-xp-air: can't map action for button %u\n",
						  button->index);
					return rc;
				}
			}
			/* the device doesn't always keep this header; write it ourselves */
			b[KXA_B_TYPE] = 0x07;
			b[KXA_B_SIZE] = KXA_BUTTONS_SIZE;
			b[KXA_B_PROFILE] = profile->index;
			rc = kxa_write_block(device, KXA_CMD_BUTTONS, profile->index,
					     b, KXA_BUTTONS_SIZE);
			if (rc)
				return rc;
		}
	}

	return 0;
}

static int
kxa_commit(struct ratbag_device *device)
{
	int rc;

	kxa_lock(device);
	rc = kxa_commit_locked(device);
	kxa_unlock(device);

	return rc;
}

static int
kxa_set_active_profile(struct ratbag_device *device, unsigned int index)
{
	struct kxa_data *drv_data = ratbag_get_drv_data(device);
	uint8_t payload[2] = { index, drv_data->profile_count };
	int rc;

	if (index >= KXA_NUM_PROFILES)
		return -EINVAL;

	kxa_lock(device);
	rc = kxa_send_write(device, KXA_CMD_PROFILE, payload, sizeof(payload));
	kxa_unlock(device);

	return rc;
}

static void
kxa_remove(struct ratbag_device *device)
{
	ratbag_close_hidraw(device);
	free(ratbag_get_drv_data(device));
}

struct ratbag_driver roccat_kone_xp_air_driver = {
	.name = "Roccat Kone XP Air",
	.id = "roccat-kone-xp-air",
	.probe = kxa_probe,
	.remove = kxa_remove,
	.commit = kxa_commit,
	.set_active_profile = kxa_set_active_profile,
};
