/* shuttlexpress-mpd.h
 * Music Player Daemon (MPD) Cilent that uses a Contour ShuttleXpress to
 * control MPD
 *
 * Version: 1.0
 * Author:  Matthew J Wolf
 * Date:    27-FEB-2019
 *
 * This file is part of shuttlexpress-mpd.
 * By Matthew J. Wolf <matthew.wolf@speciosus.net>
 *
 * Copyright 2019 Matthew J. Wolf
 *
 * shuttlexpress-mpd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * the Free Software Foundation,either version 2 of the License,
 * or (at your option) any later version.
 *
 * shuttlexpress-mpd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the shuttlexpress-mpd.
 * If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define DEFAULT_MPD_HOST "::1"
#define DEFAULT_MPD_PORT 6600

#define BUFFER_SIZE 32
#define DIAL_ROTATION_SCALE 3

#define LOCKFILE "/usr/local/var/run/shuttlexpress-mpd.pid"

// ev.type values
#define EVENT_TYPE_COMPETED 0
#define EVENT_TYPE_KEY 1
#define EVENT_TYPE_ROTATION 2

// ev.code values
#define EVENT_CODE_DIAL 7
#define EVENT_CODE_RING 8
#define EVENT_CODE_KEY0 260
#define EVENT_CODE_KEY1 261
#define EVENT_CODE_KEY2 262
#define EVENT_CODE_KEY3 263
#define EVENT_CODE_KEY4 264

struct items_status {
   char host[46];
   int port;
   int use_socket;
   int button_0;
   int button_1;
   int button_2;
   int button_3;
   int button_4;
   int dial_rotation;
   int dial_rotation_past;
   int dial_rotation_count;
   struct mpd_connection *mpd_conn;
   struct mpd_status *mpd_status;
} * items_status;

#define NUM_VALID_PREFIXES 1

static const char *valid_prefix[NUM_VALID_PREFIXES] = {
   "Contour Design ShuttleXpress",
};

void monitor_shuttlexpress_mpd(int fd_shuttlexpress,
                               struct items_status *status);
void process_shuttlexpress_event(int fd, struct input_event *ev,
                                 struct items_status *status);
int open_mpd_connection(struct items_status *status);
void get_mpd_status(struct mpd_connection *mpd_conn);
int find_shuttlexpress(int mode);
int open_shuttlexpress(const char *dev, int mode);
int AsciiDecCharToInt (char localLine[50], int start,int length);
void signal_handler(int signal);
void daemonize();
