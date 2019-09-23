/* shuttlexpress-mpd.c
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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <linux/input.h>
#include <mpd/client.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "./shuttlexpress-mpd.h"

int debug = 0;

pid_t pid, sid;
FILE *pidfile;

/*
 * Fuction : main
 * Desc    : The main fuction of the program.
 * Inputs  : Common arguments, the "--help" argument lists all the arguments.
 * Outputs :
 *            1. Errors sent to stderr and syslog.
 *            2. Process termination value.
 */
int main(int argc, char *argv[]) {

   int poll = 10;      //sec between polls, 10 miniaum

   int i = -1;
   int fd_shuttlexpress = -1;

   const char *mpd_error;

   struct mpd_connection *mpd_conn = NULL;
   struct mpd_status *mpd_status = NULL;

   struct items_status *status = malloc(sizeof( struct items_status ));

   // Set status struc initial values
   strcpy(status->host, DEFAULT_MPD_HOST);      // Default MPD host
   status->port = DEFAULT_MPD_PORT;      // Default MPD port
   status->use_socket = 0;
   status->button_0 = 0;
   status->button_1 = 0;
   status->button_2 = 0;
   status->button_3 = 0;
   status->button_4 = 0;
   status->dial_rotation = 0;
   status->dial_rotation_past = -1;
   status->dial_rotation_count = 0;
   status->mpd_conn = NULL;
   status->mpd_status = NULL;

   for ( i = 1; i < argc; i++ ) {
      if (!strcmp("-d",argv[i])) {
         debug = 1;
      }
      if (!strcmp("-h",argv[i])) {
         // MPD host
         if ( argv[i + 1] != '\0' ) {
            strcpy(status->host,argv[i + 1]);
         }
      }
      if (!strcmp("-p",argv[i])) {
         // MPD host port
         if ( argv[i + 1] != '\0' ) {
            status->port = AsciiDecCharToInt(argv[i + 1],0,(int)strlen(argv[i + 1]));
         }
      }

      // Connect to MPD on the same system via MPD's "default" Unix socket.
      if (!strcmp("-s",argv[i])) {
         status->use_socket = 1;
      }
      if (!strcmp("--help",argv[i])) {
         // Display Usage
         printf("\nusage: shuttlexpress-mpd -dhps --help\n"
                "----------------------------------------------\n"
                "-d Debug\n"
                "      Does not daemonize and displays messages\n"
                "-h MPD Host IP Address\n"
                "      Default: %s\n"
                "-p MPD Host Service Port\n"
                "      Default: %d\n"
                "-s Connect to MPD via MPD's default socket.\n"
                "      Only works when shuttlexpress-mpd and MPD\n"
                "        are running on the same system.\n"
                "      Note: MPD's default Unix socket path is\n"
                "        a MPD compile time option.\n"
                "--help Display the program usage details\n\n"
                ,DEFAULT_MPD_HOST,DEFAULT_MPD_PORT);
         return EXIT_SUCCESS;
      }
   }

   if (debug) {
      printf("Host: %s Port: %d Poll: %d Socket: %s\n",status->host,
             status->port,poll,status->use_socket ? "Yes" : "No");
   }

   openlog("shuttlexpress-mpd",LOG_PID, LOG_DAEMON);

   // Open shuttlexpress read and write.
   fd_shuttlexpress = find_shuttlexpress(O_RDWR);
   if (fd_shuttlexpress < 0) {
      fprintf(stderr, "Unable to locate shuttlexpress.\n");
      syslog(LOG_ERR,"Unable to locate shuttlexpress.");
      exit (EXIT_FAILURE);
   }

   // This program wants exclusive access to the shuttlexpress
   if(ioctl( fd_shuttlexpress, EVIOCGRAB, 1 ) < 0) {
      fprintf(stderr, "Unable to get exclusive access to the shuttlexpress: %s\n",
              strerror(errno));
      syslog(LOG_ERR,"Unable to get exclusive access to the shuttlexpress: %s",
             strerror(errno));
      exit (EXIT_FAILURE);
   }

   // Test access to MPD server the program starts
   //  -When using MPD's default Unix socket the host needs to be NULL
   //   and port needs to be 0.
   mpd_conn = mpd_connection_new(( status->use_socket ? NULL : status->host ),
                                 ( status->use_socket ? 0 : status->port ),
                                 30000);
   mpd_send_status(mpd_conn);
   mpd_status = mpd_recv_status(mpd_conn);

   if (mpd_connection_get_error(mpd_conn) != MPD_ERROR_SUCCESS) {
      mpd_error = mpd_connection_get_error_message(mpd_conn);
      fprintf(stderr, "Error: mpd connection: %s\n", mpd_error);
      syslog(LOG_ERR,"Error: mpd connection: %s", mpd_error);
      mpd_connection_free(mpd_conn);
      exit (EXIT_FAILURE);
   }

   mpd_connection_free(mpd_conn);

   // Fork Daemon
   if (!debug) {
      daemonize();
   }

   monitor_shuttlexpress_mpd(fd_shuttlexpress,status);

   close(fd_shuttlexpress);

   exit(EXIT_SUCCESS);
}

/*
 * Fuction : monitor_shuttlexpress_mpd
 * Desc    : A fuction that monitors the shuttlexpress device for state changes.
 *           The fuction calls other fuctions to process the new state / event.
 * Inputs  :
 *          int fd_shuttlexpress - The shuttlexpress file descriptor.
 *          int poll         - The polling interval in seconds.
 *          struct *status   - A items_status structure that is defined in
 *                             local shuttlexpress.h
 * Outputs : Errors sent to stderr and syslog.
 */
void monitor_shuttlexpress_mpd(int fd_shuttlexpress,
                               struct items_status *status) {

   int i = -1;
   int ret = -1;
   int events = -1;

   fd_set set;

   struct input_event ibuffer[BUFFER_SIZE];

   for (;; ) {

      // Need to reset the FD set before each select call.
      FD_ZERO(&set);
      FD_SET(fd_shuttlexpress,&set);

      ret = select(fd_shuttlexpress + 1,&set,NULL,NULL,NULL);

      if ( ret == 0 ) {           // Select Timeout
         if (debug) { printf("Select Timeout\n"); }

         continue;
      } else if ( ret == -1 ) {
         fprintf(stderr,"Select Error\n");
         syslog(LOG_ERR,"Select Error");
      }

      if (FD_ISSET(fd_shuttlexpress,&set)) {
         ret = read(fd_shuttlexpress, ibuffer,
                    sizeof( struct input_event ) * BUFFER_SIZE);
         if ( ret > 0 ) {
            events = ret / sizeof( struct input_event );
            for (i = 0; i < events; i++) {
               process_shuttlexpress_event(fd_shuttlexpress,&ibuffer[i],status);
            }
         } else {
            fprintf(stderr, "read() failed: %s\n", strerror(errno));
            syslog(LOG_ERR,"read() failed: %s", strerror(errno));
            return;
         }
      }

   }

   return;
}

/*
 * Fuction : process_shuttlexpress_event
 * Desc    : A fuction that takes some action when the state of the shuttlexpress
 *           changes.
 * Inputs  :
 *          int fd           - The shuttlexpress file descriptor.
 *          struct *ev       - A input_event structure. The structure is defined
 *                             in linux/input.h.
 *          struct *status   - A items_status structure that is defined in
 *                             local shuttlexpress.h.
 * Outputs : Errors sent to stderr and syslog.
 */
void process_shuttlexpress_event(int fd, struct input_event *ev,
                                 struct items_status *status) {

   int dial_rotation_delta = 0;

   switch (ev->type) {
   case EVENT_TYPE_COMPETED:
      break;
   case EVENT_TYPE_KEY:

      if (ev->code ==  EVENT_CODE_KEY0) {
         switch (ev->value) {

         // Button 0 - Previous Button
         case 0:
            if (debug) { printf("Button 0 UP\n"); }

            // Button debounce logic
            // -Test if button was down.
            // -Action when the button goes from down to up.
            if (status->button_0 == 1) {
               status->button_0 = 0;
               //Send MPD
               if (open_mpd_connection(status) == 0 ) {
                  if (debug) { printf("  -Previous\n"); }
                  mpd_send_previous(status->mpd_conn);
                  mpd_connection_free(status->mpd_conn);
               }
            }
            else {
               status->button_0 = 0;
            }

            break;
         case 1:
            if (debug) { printf("Button 0 Down\n"); }
            status->button_0 = 1;
            break;
         }
         break;
      }

      // Button 1 - Play
      if (ev->code ==  EVENT_CODE_KEY1) {
         switch (ev->value) {
         case 0:
            if (debug) { printf("Button 1 UP\n"); }

            // Button debounce logic
            // -Test if button was down.
            // -Action when the button goes from down to up.
            if (status->button_1 == 1) {
               status->button_1 = 0;
               if (open_mpd_connection(status) == 0 ) {
                  if (debug) { printf("  -Play\n"); }
                  mpd_send_play(status->mpd_conn);
                  mpd_connection_free(status->mpd_conn);
               }
            }
            else {
               status->button_1 = 0;
            }

            break;
         case 1:
            if (debug) { printf("Button 1 Down\n"); }
            status->button_1 = 1;
            break;
         }
         break;
      }

      // Button 2 - Pause
      if (ev->code ==  EVENT_CODE_KEY2) {
         switch (ev->value) {
         case 0:
            if (debug) { printf("Button 2 UP\n"); }

            // Button debounce logic
            // -Test if button was down.
            // -Action when the button goes from down to up.
            if (status->button_2 == 1) {
               status->button_2 = 0;
               if (open_mpd_connection(status) == 0 ) {
                  if (debug) { printf("  -Pause\n"); }
                  mpd_send_toggle_pause(status->mpd_conn);
                  mpd_connection_free(status->mpd_conn);
               }
            }
            else {
               status->button_2 = 0;
            }

            break;
         case 1:
            if (debug) { printf("Button 2 Down\n"); }
            status->button_2 = 1;
            break;
         }
         break;
      }

      // Button 3 - Stop
      if (ev->code ==  EVENT_CODE_KEY3) {
         switch (ev->value) {
         case 0:
            if (debug) { printf("Button 3 UP\n"); }

            // Button debounce logic
            // -Test if button was down.
            // -Action when the button goes from down to up.
            if (status->button_3 == 1) {
               status->button_3 = 0;
               if (open_mpd_connection(status) == 0 ) {
                  if (debug) { printf("  -Stop\n"); }
                  mpd_send_stop(status->mpd_conn);
                  mpd_connection_free(status->mpd_conn);
               }
            }
            else {
               status->button_3 = 0;
            }

            break;
         case 1:
            if (debug) { printf("Button 3 Down\n"); }
            status->button_3 = 1;
            break;
         }
         break;
      }

      // Button 4 - Next
      if (ev->code ==  EVENT_CODE_KEY4) {
         switch (ev->value) {
         case 0:
            if (debug) { printf("Button 4 UP\n"); }

            // Button debounce logic
            // -Test if button was down.
            // -Action when the button goes from down to up.
            if (status->button_4 == 1) {
               status->button_4 = 0;
               if (open_mpd_connection(status) == 0 ) {
                  if (debug) { printf("  -Next\n"); }
                  mpd_send_next(status->mpd_conn);
                  mpd_connection_free(status->mpd_conn);
               }
            }
            else {
               status->button_4 = 0;
            }

            break;
         case 1:
            if (debug) { printf("Button 4 Down\n"); }
            status->button_4 = 1;
            break;
         }
         break;
      }

      break;
   case EVENT_TYPE_ROTATION:

      // Dial Rotation
      // Dail rotation values range is 0 to 255.
      // It rolls over at 0 and 255.
      // The value decrease with left rotation.
      // The value increasses with right rotation.
      if (ev->code ==  EVENT_CODE_DIAL) {
         if (debug) { printf("   Dial Rotation: "); }

         // At Program start the ShuttleXpress's dail rotation value may not
         // zero. In order to prevent a large change in volume the first the
         // dial it rotated, set dial_rotation_past to the current value of the
         // dial.
         if (status->dial_rotation_past == -1) {
            status->dial_rotation_past = ev->value;
         }

         status->dial_rotation = ev->value;
         if (debug) { printf("%d\n",status->dial_rotation); }

         // Scaleing the rotation so that
         // shuttlexpress's range of 0 to 255 can  work nicely
         // with MPD's range of 0 to 100
         status->dial_rotation_count++;
         if (status->dial_rotation_count >= DIAL_ROTATION_SCALE ) {

            dial_rotation_delta =
               ( status->dial_rotation - status->dial_rotation_past )
               / (int)DIAL_ROTATION_SCALE;
            if (debug) { printf("   Dial Delta: %d\n",dial_rotation_delta); }
            status->dial_rotation_past = status->dial_rotation;
            status->dial_rotation_count = 0;

            if (open_mpd_connection(status) == 0 ) {
               if (debug) {printf("  -Volume Change %d\n",dial_rotation_delta); }
               mpd_send_change_volume(status->mpd_conn,dial_rotation_delta);
               mpd_connection_free(status->mpd_conn);
            }

         }

      }

      // Ring Rotation
      // Ring rotation values range is -7 to 7.
      // -7 is full left
      // 7 is full right
      // No event when the ring value is 0
      // There can be a bounce when one lets go of the ring.
      if (ev->code ==  EVENT_CODE_RING) {
         if (debug) { printf("Ring Rotation: %d\n", ev->value); }

         // Positive values - random on
         if (ev->value > 0) {
            if (open_mpd_connection(status) == 0 ) {
               if (debug) {printf("  -Random On\n");}
               mpd_send_random(status->mpd_conn,1);
               mpd_connection_free(status->mpd_conn);
            }
         }
         // Negative values - random off
         if (ev->value < 0) {
            if (open_mpd_connection(status) == 0 ) {
               if (debug) {printf("  -Random Off\n");}
               mpd_send_random(status->mpd_conn,0);
               mpd_connection_free(status->mpd_conn);
            }
         }

      }

      break;
   }

   if (debug) { fflush(stdout); }
}

int open_mpd_connection( struct items_status *status ) {
   int rc = 0;
   const char *mpd_error;

   // When using MPD's default Unix socket the host needs to be NULL
   // and port needs to be 0.
   status->mpd_conn = mpd_connection_new(( status->use_socket ? NULL : status->host ),
                                         ( status->use_socket ? 0 : status->port ),
                                         30000);

   if (mpd_connection_get_error(status->mpd_conn) != MPD_ERROR_SUCCESS) {
      mpd_error = mpd_connection_get_error_message(status->mpd_conn);
      fprintf(stderr, "Error: mpd connection: %s\n", mpd_error);
      syslog(LOG_ERR,"Error: mpd connection: %s", mpd_error);
      if (debug) { fprintf(stderr,"%s\n",mpd_error); }
      mpd_connection_free(status->mpd_conn);
      rc = -1;
   }

   return( rc );
}

/*
 * Fuction : find_shuttlexpress
 * Desc    : A fuction that finds the shuttlexpress device.
 * Inputs  : int mode - File descriptor "file status" flags.
 * Outputs : The file descriptor for the shuttlexpress device. When no shuttlexpress
 *           device was found the file descriptor value is "-1".
 */
int find_shuttlexpress(int mode) {
   int i;
   int ret,reta;
   int rc = -2;
   //int input_event_count;
   char full_file_name[PATH_MAX];
   char *dev_input_path = "/dev/input";

   struct dirent **dev_input_dirent = NULL;

   // Get listing of device input directory, /dev/input.
   ret = scandir("/dev/input",&dev_input_dirent,NULL,alphasort);
   if ( ret < 0 ) {
      fprintf(stderr,"Error - Failed to scan the device input directory: %s\n",
              strerror(errno));
      syslog(LOG_ERR,"Error - Failed to scan the device input directory: %s",
             strerror(errno));
      rc = -1;

   } else {

      for (i = 0; i < ret; i++) {

         // Only examin the /dev/input/event* device files.
         if (strstr(dev_input_dirent[i]->d_name,"event") != NULL ) {

            sprintf(full_file_name,"%s/%s",dev_input_path,
                    dev_input_dirent[i]->d_name);
            reta = open_shuttlexpress(full_file_name, mode);
            if (reta >= 0) {
               rc = reta;
               // Exit for loop
               i = ret;
            }

         }

      }
   }

   return ( rc );
}

/*
 * Fuction : open_shuttlexpress
 * Desc    : A fuction that opens the file descriptor for the shuttlexpress device.
 * Inputs  :
 *           char *dev - Filesystem device file
 *           int mode  - File descriptor "file status" flags.
 * Outputs : The file descriptor for the shuttlexpress device. When no shuttlexpress
 *           device was found the file descriptor value is "-1".
 */
int open_shuttlexpress(const char *dev, int mode) {
   int fd = -1;
   int ret;
   int i;
   int rc = -3;
   char dev_name[255];

   fd = open(dev, mode);
   if (fd < 0) {
      fprintf(stderr, "Error - Unable to open \"%s\": %s\n", dev,
              strerror(errno));
      syslog(LOG_ERR,"Error - Unable to open \"%s\": %s", dev,
             strerror(errno));
      rc = -1;
   }

   if (ioctl(fd, EVIOCGNAME(sizeof( dev_name )), dev_name) < 0) {
      fprintf(stderr, "Error - \"%s\": EVIOCGNAME failed: %s\n", dev,
              strerror(errno));
      syslog(LOG_ERR,"Error- \"%s\": EVIOCGNAME failed: %s", dev,
             strerror(errno));
      close(fd);
      rc = -2;
   }

   // it's the correct device if the prefix matches what we expect it to be
   for (i = 0; i < NUM_VALID_PREFIXES; i++) {
      ret = strncasecmp(dev_name, valid_prefix[i], strlen(valid_prefix[i]));
      if (ret == 0 ) {
         rc = fd;
      }
   }

   // When the correct device was not found close the file descriptor.
   if (rc < 0) {
      close(fd);
   }

   return ( rc );
}

/*
 * Fuction : AsciiDecCharToInt
 * Desc    : A fuction that converts a ASCII charater string to an "int".
 * Inputs  :
 *           char localLine - String of ASCII charaters.
 *           int start     - The string array index value for the frist charater
 *           int length    - The length of the ASCII charater string.
 * Outputs : int out - The "int" value for the input ASCII charater string.
 */
int AsciiDecCharToInt (char localLine[50], int start,int length) {
   int i = 0;
   int tmp = -1;
   int out = 0;

   for (i = 0; i < length; i++) {

      tmp =  localLine[start + i] - '0';

      if ( i == ( length - 1 ) ) {
         out = out + tmp;
      } else {
         out = out + tmp;
         out = out * 10;
      }

   }

   return out;
}

/*
 * Fuction : signal_handler
 * Desc    : The signal handler fuction that is registered with system kernel
 *           via a sigaction structure.
 * Inputs  : int signal - The system signal sent to the running process.
 * Outputs : Process termination value.
 */
void signal_handler(int signal) {

   switch (signal) {
   case SIGTERM:
      syslog(LOG_NOTICE,"Received SIGTERM: Exiting");
      unlink(LOCKFILE);
      exit(EXIT_SUCCESS);
      break;
   case SIGINT:
      syslog(LOG_NOTICE,"Received SIGINT: Exiting");
      unlink(LOCKFILE);
      exit(EXIT_SUCCESS);
      break;
   case SIGKILL:
      syslog(LOG_NOTICE,"Received SIGKILL: Exiting");
      unlink(LOCKFILE);
      exit(EXIT_SUCCESS);
      break;
   }

}

/*
 * Fuction : daemonize
 * Desc    : A fuction the daemonizes the process.
 * Inputs  : None
 * Outputs : None - A child process.
 */
void daemonize() {
   int lf_fd;
   char buf[16];
   pid_t pid, sid;

   struct flock lf_flock;
   struct rlimit rl;
   struct sigaction sa;

   // Change the file mode mask
   umask(0);

   // Get the max limit of file descriptors
   if( getrlimit(RLIMIT_NOFILE, &rl) < 0 ) {
      syslog(LOG_ERR,"Can get file limit: %s",strerror(errno));
      exit(EXIT_FAILURE);
   }

   // Add comment
   if ( ( pid = fork()) < 0 ) {
      syslog(LOG_ERR,"Unable to create child process: %s",
             strerror(errno));
      exit(EXIT_FAILURE);
   }

   if (pid > 0) {      // Parent Exit
      exit(EXIT_SUCCESS);
   }

   // Get new session ID for child process.
   // Become session lead to drop controlling TTY.
   if ( ( sid = setsid()) < 0 ) {
      syslog(LOG_ERR,"Child session ID error: %s",strerror(errno));
      exit(EXIT_FAILURE);
   }

   // Chnage working directory to root. This do that the daemon process
   // will not be able to make and file system changes or unmount any file
   // system.
   if (chdir("/") < 0 ) {
      syslog(LOG_ERR,"Can change working directory to /: %s",
             strerror(errno));
      exit(EXIT_FAILURE);
   }

   // Setup signal handler with system kernel.
   // Clear the signal mask so that no new TTYs will be opened.
   sa.sa_handler = signal_handler;
   sigemptyset(&sa.sa_mask);
   sa.sa_flags = 0;
   sigaction(SIGTERM,&sa,NULL);
   sigaction(SIGINT,&sa,NULL);
   sigaction(SIGKILL,&sa,NULL);

   // Create lock / pid file.
   lf_fd = open(LOCKFILE, O_RDWR | O_CREAT,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
   if (lf_fd < 0) {
      syslog(LOG_ERR,"Can not open lock file %s: %s",LOCKFILE,strerror(errno));
      exit(EXIT_FAILURE);
   }

   // Lock the lock / pid file
   lf_flock.l_type = F_WRLCK;
   lf_flock.l_start = 0;
   lf_flock.l_whence = SEEK_SET;
   lf_flock.l_len = 0;

   if ( fcntl(lf_fd, F_SETLK, &lf_flock) < 0 ) {
      if (errno == EACCES || errno == EAGAIN) {
         syslog(LOG_ERR,"Lock file access issue %s: %s",LOCKFILE,strerror(errno));
         close(lf_fd);
         exit(EXIT_FAILURE);
      }
      syslog(LOG_ERR,"Can not lock %s: %s",LOCKFILE,strerror(errno));
      close(lf_fd);
      exit(EXIT_FAILURE);
   }

   // Write the process PID into the lock file.
   ftruncate(lf_fd,0);
   sprintf(buf,"%ld", (long)getpid());
   write(lf_fd,buf,strlen(buf) + 1);

   // Close out the standard file descriptors
   close(STDIN_FILENO);
   close(STDOUT_FILENO);
   close(STDERR_FILENO);

   syslog(LOG_NOTICE,"Start Up");

   return;
}
