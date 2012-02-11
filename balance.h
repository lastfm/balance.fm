/*
 * balance.h
 */

/*
 * $Id: balance.h,v 1.1 2010/01/29 10:40:16 t Exp $
 */

#include <stdio.h>
#include <stdarg.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#ifndef NO_MMAP
#include <unistd.h>
#include <sys/mman.h>
#endif

#ifdef __FreeBSD__
#define BalanceBSD 1
#endif

#ifdef bsdi
#define BalanceBSD 1
#endif

#ifdef BSD
#define BalanceBSD 1
#endif

#ifdef MAC_OS_X_VERSION_10_4
#define BalanceBSD 1
#endif

#ifndef BalanceBSD
#include <sys/resource.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/shm.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>        /* for TCP_NODELAY definition */

#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
# define BALANCE_CAN_KEEPALIVE 1
#else
# define BALANCE_CAN_KEEPALIVE 0
#endif

/* solaris 9, solaris 10 do not have INADDR_NONE */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

#define MAXTXSIZE       (32*1024)
#define FILENAMELEN     1024
/*
 * this should be a directory that isn't cleaned up periodically, or at
 * reboot of the machine (/tmp is cleaned at reboot on many OS versions)
 */
#define SHMDIR          "/var/run/balance/"
#define SHMFILESUFFIX   ".shm"

#define MAXCHANNELS             64      /* max channels in group          */
#define MAXGROUPS               16      /* max groups                     */
#define MAXINPUTLINE            128     /* max line in input mode         */
#define DEFAULTTIMEOUT          5       /* timeout for unreachable hosts  */
#define DEFAULTSELTIMEOUT       0       /* timeout for select             */

enum channel_status {
  CS_DISABLED,                  /* hard disabled (manually in shell)  */
  CS_ENABLED,                   /* enabled                            */
  CS_DISABLED_SOFT              /* soft disabled (by monitoring)      */
};

typedef struct {
  int time;
  int intvl;
  int probes;
} KEEPALIVE;

typedef struct {
  enum channel_status status;
  int port;
  struct in_addr ipaddr;
  int c;                        /* current # of connections           */
  int tc;                       /* total # of connections             */
  int maxc;                     /* max # of connections, 0 = no limit */
  unsigned long long bsent;     /* bytes sent                         */
  unsigned long long breceived; /* bytes received                     */
} CHANNEL;

#define GROUP_RR        0       /* Round Robin            */
#define GROUP_HASH      1       /* Hash on Client Address */

typedef struct {
  int nchannels;                /* number of channels in group         */
  int current;                  /* current channel in group            */
  int type;                     /* either GROUP_RR or GROUP_HASH       */
  CHANNEL channels[MAXCHANNELS];
} GROUP;

typedef struct {
  int   release;
  int   subrelease;
  int   patchlevel;
  int   pid;
  int   ngroups;
  GROUP groups[MAXGROUPS];
} COMMON;

/*
 * Macros to access various elements of struct GROUP and struct CHANNEL
 * within COMMON array
 *
 * a       pointer to variable of type COMMON
 * g       group index
 * i       channel index
 */

#define cmn_group(a,g)           ((a)->groups[(g)])
#define grp_nchannels(a,g)       (cmn_group((a),(g)).nchannels)
#define grp_current(a,g)         (cmn_group((a),(g)).current)
#define grp_type(a,g)            (cmn_group((a),(g)).type)
#define grp_channel(a,g,i)       (cmn_group((a),(g)).channels[(i)])
#define chn_status(a,g,i)        (grp_channel((a),(g),(i)).status)
#define chn_port(a,g,i)          (grp_channel((a),(g),(i)).port)
#define chn_ipaddr(a,g,i)        (grp_channel((a),(g),(i)).ipaddr)
#define chn_c(a,g,i)             (grp_channel((a),(g),(i)).c)
#define chn_tc(a,g,i)            (grp_channel((a),(g),(i)).tc)
#define chn_maxc(a,g,i)          (grp_channel((a),(g),(i)).maxc)
#define chn_bsent(a,g,i)         (grp_channel((a),(g),(i)).bsent)
#define chn_breceived(a,g,i)     (grp_channel((a),(g),(i)).breceived)

/*
 * function prototypes
 */
unsigned int hash_fold(const void *, int);
ssize_t writen(int, const unsigned char *, size_t);
