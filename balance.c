/*
 * balance - a balancing tcp proxy
 * $Revision: 3.54 $
 *
 * Copyright (c) 2000-2009,2010 by Thomas Obermair (obermair@acm.org)
 * and Inlab Software GmbH (info@inlab.de), Gruenwald, Germany.
 * All rights reserved.
 *
 * Thanks to Bernhard Niederhammer for the initial idea and heavy
 * testing on *big* machines ...
 *
 * For license terms, see the file COPYING in this directory.
 *
 * This program is dedicated to Richard Stevens...
 *
 *  3.54
 *    fixed hash_fold bug regarding incoming IPv4 and IPv6 source addresses
 *  3.52
 *    thanks to David J. Jilk from Standing Cloud, Inc. for the following:
 *    added "nobuffer" functionality to interactive shell IO
 *    added new "assign" interactive command
 *    fixed locking bug
 *  3.50
 *    new option -6 forces IPv6 bind (hints.ai_family = AF_INET6)
 *  3.49
 *    ftok() patch applied (thanks to Vladan Djeric)
 *  3.48
 *    Problems with setting IPV6_V6ONLY socket option are now handled
 *    more nicely with a syslog warning message
 *  3.42
 *    Balance compiles now on systems where IPV6_V6ONLY is undefined
 *  3.35
 *    bugfix in autodisable code (thanks to Michael Durket)
 *  3.34
 *    syslog logging added (finally)
 *    -a autodisable option added (thanks to Mitsuru IWASAKI)
 *  3.33
 *    SO_KEEPALIVE switched on (suggested and implemented by A. Fluegel)
 *    new option -M to use a memory mapped file instead of IPC shared memory
 *  3.32
 *    /var/run/balance may already exist (thanks to Thomas Steudten)
 *  3.31
 *    TCP_NODELAY properly switched on (thanks to Kurt J. Lidl).
 *  3.30
 *    Code cleanups and fixes (thanks to Kurt J. Lidl)
 *  3.28
 *    Code cleanup's (thanks to Thomas Steudten)
 *    MRTG-Interface (thanks to Brian McCann for the suggestion)
 *  3.26
 *    bugfix: master process was not found with balance -i
 *    unused variable pid removed (BSD)
 *  3.24
 *    bugfix in channel/group argument parsing (thanks to Enrique G. Paredes)
 *    permisions+error messages improvements (thanks to Wojciech Sobczuk)
 *  3.22
 *    writelock and channelcount patch from Stoyan Genov
 *    balance exit codes fix from Chris Wilson
 *    /var/run/balance is tried to be autocreated (if not there)
 *    close of 0,1,2 on background operation
 *  3.19
 *    -h changed to -H
 *  3.17
 *    -h option added
 *    thanks to Werner Maier
 *  3.16
 *    fixed missing save_tmout initialization
 *    thanks to Eric Andresen
 *  3.15
 *    first -B support
 *  3.14
 *    -Wall cleanup
 *  3.12
 *    alarm(0) added, thanks to Jon Christensen
 *  3.11
 *    Bugfix
 *  3.10
 *    Bugfix for RedHat 7.2
 *  3.9
 *    Moved rendezvous file to /var/run and cleaned main(), thanks to
 *    Kayne Naughton
 *  3.8
 *    move to sigaction(), thanks to Kayne Naughton
 *  3.5
 *    Select-Timeout, thanks to Jeff Buhlmann
 *  3.2
 *    Hash groups and some other improvements
 *  2.24:
 *    'channel 2 overload' problem fixed, thanks to Ed "KuroiNeko"
 *  2.26:
 *    'endless loop error' fixed, thanks to Anthony Baxter
 *  2.27:
 *    strcmp on NULL removed, thanks to Jay. D. Allen
 *  2.28:
 *    bsent and breceived now unsigned to avoid negative values,
 *    thanks to Anthony Baxter
 *  2.29:
 *    error in setaddress() fixed, thanks to Dirk Datzert
 *  2.30:
 *    fixing #includes for *bsd compability
 *  2.31:
 *  2.32:
 *    redefied SIGCHLD handling to be compatible with FreeBSD 4.3,
 *    BSD/OS 4.2 and BSD/OS 4.0.1
 *  2.33
 *    finally included SO_REUSEADDR
 *
 */

#include "balance.h"

// TODO: those need to be set automatically from the debian/changelog
static int release = 1;
static int subrelease = 0;
static int patchlevel = 0;

static char rendezvousfile[FILENAMELEN];
static int rendezvousfd;
#ifndef NO_MMAP
static int shmfilefd;
#endif

COMMON *common;

static int hashfailover = 0;
static int autodisable = 0;
static int debugflag = 0;
static int foreground = 0;
static int packetdump = 0;
static int interactive = 0;
static int shmmapfile = 0;
static int bindipv6 = 0;
static int no_std_handles = 0;

static int sockbufsize = 32768;

static int connect_timeout;

static char *bindhost = NULL;
static char *outbindhost = NULL;

static struct timeval sel_tmout  = { 0, 0 }; /* seconds, microseconds */
static struct timeval save_tmout = { 0, 0 }; /* seconds, microseconds */

static KEEPALIVE keepalive_server = { 0, 0, 0 };
static KEEPALIVE keepalive_client = { 0, 0, 0 };

static void log_msg(int priority, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if (no_std_handles) {
    vsyslog(priority, fmt, ap);
  } else {
    fprintf(stderr, "balance.fm: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
  }
  va_end(ap);
}

static void log_perror(int priority, const char *str)
{
  const char *err = strerror(errno);
  if (no_std_handles) {
    syslog(priority, "%s: %s", str, err);
  } else {
    fprintf(stderr, "balance.fm: %s: %s\n", str, err);
    fflush(stderr);
  }
}

static void debug(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if (debugflag && !no_std_handles) {
    vfprintf(stderr, fmt, ap);
    fflush(stderr);
  }
  va_end(ap);
}

int err_dump(const char *text)
{
  log_msg(LOG_ERR, "%s", text);
  exit(EX_UNAVAILABLE);
}

static int create_serversocket(const char *node, const char *service)
{
  struct addrinfo hints;
  struct addrinfo *results;
  int srv_socket, status, sockopton, sockoptoff;

  bzero(&hints, sizeof(hints));
  hints.ai_flags = AI_PASSIVE;

  if(bindipv6) {
    debug("using AF_INET6\n");
    hints.ai_family = AF_INET6;
  } else {
    debug("using AF_UNSPEC\n");
    hints.ai_family = AF_UNSPEC;
  }
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  status = getaddrinfo(node, service, &hints, &results);
  if(status != 0) {
    log_msg(LOG_ERR, "error at getaddrinfo: %s", gai_strerror(status));
    log_msg(LOG_ERR, "exiting.");
    exit(EX_OSERR);
  }

  if(results == NULL) {
    log_msg(LOG_ERR, "no matching results at getaddrinfo");
    log_msg(LOG_ERR, "exiting");
    exit(EX_OSERR);
  }

  srv_socket = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
  if(srv_socket < 0) {
    log_perror(LOG_ERR, "socket");
    exit(EX_OSERR);
  }

  sockoptoff = 0;

#if defined(IPV6_V6ONLY)
  status = setsockopt(srv_socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*) &sockoptoff, sizeof(sockoptoff));
  if(status < 0) {
    syslog(LOG_WARNING,"setsockopt(IPV6_V6ONLY=0) failed");
  }
#endif

  sockopton = 1;

  status = setsockopt(srv_socket, SOL_SOCKET, SO_REUSEADDR, (char*) &sockopton, sizeof(sockopton));

  if(status < 0) {
    log_perror(LOG_ERR, "setsockopt(SO_REUSEADDR=1)");
    exit(EX_OSERR);
  }

  status = bind(srv_socket, results->ai_addr, results->ai_addrlen);
  if(status < 0) {
    log_perror(LOG_ERR, "bind");
    exit(EX_OSERR);
  }

  status = listen(srv_socket, SOMAXCONN);
  if(status < 0) {
    log_perror(LOG_ERR, "listen");
    exit(EX_OSERR);
  }

  return(srv_socket);
}

/* locking ... */

static int a_readlock(off_t start __attribute__((unused)), off_t len __attribute__((unused)))
{
  int rc;
  struct flock fdata;
  fdata.l_type = F_RDLCK;
  fdata.l_whence = SEEK_SET;
  fdata.l_start = 0;
  fdata.l_len = 0;
  // fdata.l_sysid=0;
  // fdata.l_pid=0;
repeat:
  if ((rc = fcntl(rendezvousfd, F_SETLKW, &fdata)) < 0) {
    if (errno == EINTR) {
      goto repeat;              // 8-)
    } else {
      log_perror(LOG_ERR, "readlock");
      exit(EX_OSERR);
    }
  }
  return (rc);
}

static void b_readlock(void)
{
  a_readlock(0, 0);
}

static void c_readlock(int group, int channel)
{
  a_readlock(((char *) &(grp_channel(common, group, channel))) -
             (char *) common, sizeof(CHANNEL));
}

static int a_writelock(off_t start __attribute__((unused)), off_t len __attribute__((unused)))
{
  int rc;
  struct flock fdata;
  fdata.l_type = F_WRLCK;
  fdata.l_whence = SEEK_SET;
  fdata.l_start = 0;
  fdata.l_len = 0;
  // fdata.l_sysid=0;
  // fdata.l_pid=0;
repeat:
  if ((rc = fcntl(rendezvousfd, F_SETLKW, &fdata)) < 0) {
    if (errno == EINTR) {
      goto repeat;              // 8-)
    } else {
      log_perror(LOG_ERR, "a_writelock");
      exit(EX_OSERR);
    }
  }
  return (rc);
}

static void b_writelock(void)
{
  a_writelock(0, 0);
}

static void c_writelock(int group, int channel)
{
  a_writelock(((char *) &(grp_channel(common, group, channel))) -
              (char *) common, sizeof(CHANNEL));
}

static int a_unlock(off_t start __attribute__((unused)), off_t len __attribute__((unused)))
{
  int rc;
  struct flock fdata;
  fdata.l_type = F_UNLCK;
  fdata.l_whence = SEEK_SET;
  fdata.l_start = 0;
  fdata.l_len = 0;
  // fdata.l_sysid=0;
  // fdata.l_pid=0;
repeat:
  if ((rc = fcntl(rendezvousfd, F_SETLK, &fdata)) < 0) {
    if (errno == EINTR) {
      goto repeat;              // 8-)
    } else {
      log_perror(LOG_ERR, "a_unlock");
      exit(EX_OSERR);
    }
  }
  return (rc);
}

static void b_unlock(void)
{
  a_unlock(0, 0);
}

static void c_unlock(int group, int channel)
{
  a_unlock(((char *) &(grp_channel(common, group, channel))) -
           (char *) common, sizeof(CHANNEL));
}

static void *shm_malloc(char *file, int size)
{
  char *data = NULL;
  key_t key;
  int shmid;

  if(shmmapfile){
#ifndef NO_MMAP
    char shmfile[FILENAMELEN];

    strcpy(shmfile, file);
    strcat(shmfile, SHMFILESUFFIX);
    shmfilefd = open(shmfile, O_RDWR | O_CREAT, 0644);
    if(shmfilefd < 0) {
      log_msg(LOG_WARNING, "Warning: Cannot open file `%s', switching to IPC", shmfile);
      shmmapfile = 0;
    }
    if(shmmapfile) {
      if(ftruncate(shmfilefd, size) < 0) {
        log_msg(LOG_WARNING, "Warning: Cannot set file size on `%s', switching to IPC", shmfile);
        close(shmfilefd);
        shmmapfile = 0;
      }
    }
    if(shmmapfile) {
      data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shmfilefd, 0);
      if(!data || data == MAP_FAILED) {
        log_msg(LOG_WARNING, "Warning: Cannot map file `%s', switching to IPC", shmfile);
        close(shmfilefd);
        shmmapfile = 0;

      }
    }
#endif
  }

  if(!shmmapfile){

#if defined (__SVR4) && defined (__sun)

    /* vdjeric:
       Solaris ftok() causes frequent collisions because it uses
       only the lower 12 bits of the inode number in the 'key'.
       See: http://bugs.opensolaris.org/bugdatabase/view_bug.do?bug_id=4265917
    */

    FILE *rendezvousfp = NULL;
    struct timeval ct;
    long int seed;
    int i;

    if ((rendezvousfp = fdopen(rendezvousfd, "w+")) == NULL) {
      log_perror(LOG_ERR, "fdopen");
      exit(EX_OSERR);
    }

    if ((fscanf(rendezvousfp, "0x%x\n", &key)) <= 0) {
      gettimeofday(&ct, NULL);
      seed = ct.tv_usec * getpid();
      srand(seed);

      /* Solaris rand() returns values between 0 and 0x7fff,
         so generate key byte by byte */
      key = 0;
      for (i = 0; i < sizeof(key); i++) {
          key = (key << 8) | (rand() & 0xff);
      }

      if(fseek(rendezvousfp, 0, SEEK_SET) == -1) {
        log_perror(LOG_ERR, "fseek");
        exit(EX_OSERR);
      }
      if (fprintf(rendezvousfp, "0x%08x\n", key) == -1) {
        log_perror(LOG_ERR, "fprintf");
        exit(EX_OSERR);
      }
      fflush(rendezvousfp);
    }
#else
    if ((key = ftok(file, 'x')) == -1) {
      log_perror(LOG_ERR, "ftok");
      exit(EX_OSERR);
    }
#endif

    if ((shmid = shmget(key, size, 0644 | IPC_CREAT)) == -1) {
      log_perror(LOG_ERR, "shmget");
      exit(EX_OSERR);
    }

    data = shmat(shmid, (void *) 0, 0);
    if (data == (char *) (-1)) {
      log_perror(LOG_ERR, "shmat");
      exit(EX_OSERR);
    }
  }

  return (data);
}

/* readable output of a packet (-p) */

static void print_packet(const unsigned char *s, int l)
{
  int i, cc;
  cc = 0;
  for (i = 0; i < l; i++) {
    if (isprint(s[i]) && isascii(s[i])) {
      if (s[i] == '\\') {
        printf("\\\\");
        cc += 2;
      } else {
        printf("%c", s[i]);
        cc++;
      }
    } else {
      printf("\\%02X", s[i]);
      cc += 3;
      if (s[i] == '\n') {
        printf("\n");
        cc = 0;
      }
    }
    if (cc > 80) {
      printf("\n");
      cc = 0;
    }
  }
  printf("\n");
}

static int getport(const char *port)
{
  struct servent *sp;
  sp = getservbyname(port, "tcp");
  if (sp == NULL) {
    return (atoi(port));
  } else {
    return (ntohs(sp->s_port));
  }
}

static void setipaddress(struct in_addr *ipaddr, const char *string)
{
  struct hostent *hent;
  hent = gethostbyname(string);
  if (hent == NULL) {
    if ((ipaddr->s_addr = inet_addr(string)) == INADDR_NONE) {
      log_msg(LOG_ERR, "unknown or invalid address [%s]", string);
      exit(EX_DATAERR);
    }
  } else {
    memcpy(ipaddr, hent->h_addr, hent->h_length);
  }
}

static void setaddress(struct in_addr *ipaddr, int *port, const char *string,
                       int default_port, int *maxc)
{
  char *host_string = NULL;
  char *port_string = NULL;
  char *maxc_string = NULL;
  char *dup_string = NULL;
  char *p = NULL;
  char *q = NULL;

  struct hostent *hent;

  if ((dup_string = strdup(string)) == NULL) {
    log_perror(LOG_ERR, "strdup");
    exit(EX_OSERR);
  }

  host_string = dup_string;
  p = index(dup_string, ':');

  if (p != NULL) {
    *p = '\000';
    port_string = p + 1;
    if ((q = index(port_string, ':')) != NULL) {
      *q = '\000';
      maxc_string = q + 1;
    } else {
      maxc_string = "";
    }
  } else {
    port_string = "";
    maxc_string = "";
  }

  // fix for RedHat 7.0/7.1 choke on strcmp with NULL

  if (port_string != NULL && !strcmp(port_string, ""))
    port_string = NULL;
  if (maxc_string != NULL && !strcmp(maxc_string, ""))
    maxc_string = NULL;

  hent = gethostbyname(dup_string);
  if (hent == NULL) {
    if ((ipaddr->s_addr = inet_addr(dup_string)) == INADDR_NONE) {
      log_msg(LOG_ERR, "unknown or invalid address [%s]", dup_string);
      exit(EX_DATAERR);
    }
  } else {
    memcpy(ipaddr, hent->h_addr, hent->h_length);
  }

  if (port_string != NULL) {
    *port = getport(port_string);
  } else {
    *port = default_port;
  }

  if (maxc_string != NULL) {
    *maxc = atoi(maxc_string);
  }
  free(dup_string);
}

static int setaddress_noexitonerror(struct in_addr *ipaddr, int *port,
                                    const char *string, int default_port)
{
  char *dup_string = strdup(string);

  if (dup_string == NULL) {
    return 0;
  }

  char *host_string = strtok(dup_string, ":");
  char *port_string = strtok(NULL, ":");
  struct hostent *hent = gethostbyname(host_string);

  if (hent == NULL) {
    if ((ipaddr->s_addr = inet_addr(string)) == INADDR_NONE) {
      free(dup_string);
      return 0;
    }
  } else {
    memcpy(ipaddr, hent->h_addr, hent->h_length);
  }

  if (port_string != NULL) {
    *port = getport(port_string);
  } else {
    *port = default_port;
  }

  free(dup_string);

  return 1;
}

static int forward(int fromfd, int tofd, int groupindex, int channelindex)
{
  ssize_t rc;
  unsigned char buffer[MAXTXSIZE];

  rc = read(fromfd, buffer, MAXTXSIZE);

  if (packetdump) {
    printf("-> %d\n", (int) rc);
    print_packet(buffer, rc);
  }

  if (rc <= 0) {
    return (-1);
  } else {
    if (writen(tofd, buffer, rc) != rc) {
      return (-1);
    }
    c_writelock(groupindex, channelindex);
    chn_bsent(common, groupindex, channelindex) += rc;
    c_unlock(groupindex, channelindex);
  }
  return (0);
}

static int backward(int fromfd, int tofd, int groupindex, int channelindex)
{
  ssize_t rc;
  unsigned char buffer[MAXTXSIZE];

  rc = read(fromfd, buffer, MAXTXSIZE);

  if (packetdump) {
    printf("-< %d\n", (int) rc);
    print_packet(buffer, rc);
  }

  if (rc <= 0) {
    return (-1);
  } else {
    if (writen(tofd, buffer, rc) != rc) {
      return (-1);
    }
    c_writelock(groupindex, channelindex);
    chn_breceived(common, groupindex, channelindex) += rc;
    c_unlock(groupindex, channelindex);
  }
  return (0);
}

static void set_socket_options(int s, const KEEPALIVE *ka)
{
  int optval = 1;

  /* failure is acceptable */
  (void) setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
  (void) setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

#if BALANCE_CAN_KEEPALIVE
  if (ka->time > 0)
  {
    optval = ka->time;
    if (setsockopt(s, SOL_TCP, TCP_KEEPIDLE, &optval, sizeof(optval)) < 0) {
      log_perror(LOG_ERR, "setsockopt(TCP_KEEPIDLE)");
      exit(EX_OSERR);
    }
    optval = ka->intvl;
    if (setsockopt(s, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof(optval)) < 0) {
      log_perror(LOG_ERR, "setsockopt(TCP_KEEPINTVL)");
      exit(EX_OSERR);
    }
    optval = ka->probes;
    if (setsockopt(s, SOL_TCP, TCP_KEEPCNT, &optval, sizeof(optval)) < 0) {
      log_perror(LOG_ERR, "setsockopt(TCP_KEEPCNT)");
      exit(EX_OSERR);
    }
  }
#endif
}

/*
 * the connection is really established, let's transfer the data
 *  as efficient as possible :-)
 */

static void stream2(int clientfd, int serverfd, int groupindex, int channelindex)
{
  fd_set readfds;
  int fdset_width;
  int sr;

  fdset_width = ((clientfd > serverfd) ? clientfd : serverfd) + 1;

  set_socket_options(clientfd, &keepalive_client);
  set_socket_options(serverfd, &keepalive_server);

  for (;;) {

    FD_ZERO(&readfds);
    FD_SET(clientfd, &readfds);
    FD_SET(serverfd, &readfds);
    /*
     * just in case this system modifies the timeout values,
     * refresh the values from a saved copy of them.
     */
    sel_tmout = save_tmout;

    for (;;) {
      if (sel_tmout.tv_sec || sel_tmout.tv_usec) {
        sr = select(fdset_width, &readfds, NULL, NULL, &sel_tmout);
      } else {
        sr = select(fdset_width, &readfds, NULL, NULL, NULL);
      }
      if ((save_tmout.tv_sec || save_tmout.tv_usec) && !sr) {
        c_writelock(groupindex, channelindex);
        chn_c(common, groupindex, channelindex) -= 1;
        c_unlock(groupindex, channelindex);
        log_msg(LOG_ERR, "timed out after %d seconds", (int) save_tmout.tv_sec);
        exit(EX_UNAVAILABLE);
      }
      if (sr < 0 && errno != EINTR) {
        log_perror(LOG_ERR, "select");
        c_writelock(groupindex, channelindex);
        chn_c(common, groupindex, channelindex) -= 1;
        c_unlock(groupindex, channelindex);
        exit(EX_UNAVAILABLE);
      }
      if (sr > 0)
        break;
    }

    if (FD_ISSET(clientfd, &readfds)) {
      if (forward(clientfd, serverfd, groupindex, channelindex) < 0) {
        break;
      }
    } else {
      if (backward(serverfd, clientfd, groupindex, channelindex) < 0) {
        break;
      }
    }
  }
  c_writelock(groupindex, channelindex);
  chn_c(common, groupindex, channelindex) -= 1;
  c_unlock(groupindex, channelindex);
  exit(EX_OK);
}

static void alrm_handler(int signo __attribute__((unused)))
{
}

void usr1_handler(int signo) {
}

static void chld_handler(int signo __attribute__((unused)))
{
  int status;
  while (waitpid(-1, &status, WNOHANG) > 0);
}

/*
 * a channel in a group is selected and we try to establish a connection
 */

static void *stream(int arg, int groupindex, int index, const void *client_address,
                    int client_address_size)
{
  int startindex;
  int sockfd;
  int clientfd;
  struct sigaction alrm_action;
  struct sockaddr_in serv_addr;

  startindex = index;           // lets keep where we start...
  clientfd = arg;

  for (;;) {

    debug("trying group %d channel %d ... ", groupindex, index);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      log_perror(LOG_ERR, "socket");
      exit(EX_OSERR);
    }

    (void) setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sockbufsize,
      sizeof(sockbufsize));
    (void) setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockbufsize,
      sizeof(sockbufsize));

    /*
     *  if -B is specified, balance tries to bind to it even on
     *  outgoing connections
     */

    if (outbindhost != NULL) {
      struct sockaddr_in outbind_addr;
      bzero(&outbind_addr, sizeof(outbind_addr));
      outbind_addr.sin_family = AF_INET;
      setipaddress(&outbind_addr.sin_addr, outbindhost);
      if (bind
          (sockfd, (struct sockaddr *) &outbind_addr,
           sizeof(outbind_addr)) < 0) {
      }
    }

    b_readlock();
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr =
        chn_ipaddr(common, groupindex, index).s_addr;
    serv_addr.sin_port = htons(chn_port(common, groupindex, index));
    b_unlock();

    alrm_action.sa_handler = alrm_handler;
    alrm_action.sa_flags = 0;   // don't restart !
    sigemptyset(&alrm_action.sa_mask);
    sigaction(SIGALRM, &alrm_action, NULL);
    alarm(connect_timeout);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      if (errno == EINTR) {
        debug("timeout group %d channel %d\n", groupindex, index);
      } else {
        debug("connection refused group %d channel %d\n", groupindex, index);
      }

      /* here we've received an error (either 'timeout' or 'connection refused')
       * let's start some magical failover mechanisms
       */

      c_writelock(groupindex, index);
      chn_c(common, groupindex, index)--;
      if(autodisable) {
        if(chn_status(common, groupindex, index) != 0) {
          log_msg(LOG_NOTICE, "connection failed group %d channel %d", groupindex, index);
          log_msg(LOG_NOTICE, "%s:%d needs to be enabled manually using balance.fm -i after the problem is solved", inet_ntoa(serv_addr.sin_addr), ntohs(serv_addr.sin_port));
          chn_status(common, groupindex, index) = 0;
        }
      }
      c_unlock(groupindex, index);

      b_readlock();
      for (;;) {
        for (;;) {
          if (grp_type(common, groupindex) == GROUP_RR || hashfailover == 1) {
            index++;
            if (index >= grp_nchannels(common, groupindex)) {
              index = 0;
            }
            if (index == startindex) {
              index = -1;       // Giveup
              break;
            }
            if (chn_status(common, groupindex, index) == 1 &&
                (chn_maxc(common, groupindex, index) == 0 ||
                 (chn_c(common, groupindex, index) <
                  chn_maxc(common, groupindex, index)))) {
              break;            // new index found
            } else {
              continue;
            }
          } else if (grp_type(common, groupindex) == GROUP_HASH) {

            // If the current group is type hash, we giveup immediately
            index = -1;
            break;
          } else {
            err_dump("PANIC: invalid group in stream()");
          }
        }

        if (index >= 0) {
          // neuer index in groupindex-group found...
          break;
        } else {
        again:
          groupindex++;
          if (groupindex >= MAXGROUPS) {
            // giveup, index=-1.
            break;
          } else {
            if (grp_type(common, groupindex) == GROUP_RR) {

              if (grp_nchannels(common, groupindex) > 0) {
                index = grp_current(common, groupindex);
                startindex = index;     // This fixes the "endless loop error"
                                        // with all hosts being down and one
                                        // in the last group... (from Anthony Baxter)
              } else {
                goto again;
              }
              break;
            } else if (grp_type(common, groupindex) == GROUP_HASH) {
              unsigned int uindex;
              uindex = hash_fold(&(((struct sockaddr_in6 *) &client_address)->sin6_addr), client_address_size);

              debug("HASH-method: fold returns %u\n", uindex);

              index = uindex % grp_nchannels(common, groupindex);
              debug("modulo %d gives %d\n", grp_nchannels(common, groupindex), index);

              if (chn_status(common, groupindex, index) == 1 &&
                  (chn_maxc(common, groupindex, index) == 0 ||
                   (chn_c(common, groupindex, index) <
                    chn_maxc(common, groupindex, index)))
                  ) {
                break;
              } else {
                goto again;     // next group !
              }
            } else {
              err_dump("PANIC: invalid group in stream()");
            }
          }
        }
      }
      // we drop out here with a new index

      b_unlock();

      if (index >= 0) {
        // lets try it again
        close(sockfd);
        c_writelock(groupindex, index);
        chn_c(common, groupindex, index) += 1;
        chn_tc(common, groupindex, index) += 1;
        c_unlock(groupindex, index);
        continue;
      } else {
        break;
      }

    } else {
      alarm(0);                 // Cancel the alarm since we successfully connected
      debug("connect to channel %d successful\n", index);
      // this prevents the 'channel 2 overload problem'

      b_writelock();
      grp_current(common, groupindex) = index;
      grp_current(common, groupindex)++;
      if (grp_current(common, groupindex) >=
          grp_nchannels(common, groupindex)) {
        grp_current(common, groupindex) = 0;
      }
      b_unlock();

      // everything's fine ...

      stream2(clientfd, sockfd, groupindex, index);
      // stream2 bekommt den Channel-Index mit
      // stream2 never returns, but just in case...
      break;
    }
  }

  close(sockfd);
  exit(EX_OK);
}

static void usage(void)
{
  fprintf(stderr," _           _                         __\n");
  fprintf(stderr,"| |__   __ _| | __ _ _ __   ___ ___   / _|_ __ ___\n");
  fprintf(stderr,"| '_ \\ / _` | |/ _` | '_ \\ / __/ _ \\ | |_| '_ ` _ \\\n");
  fprintf(stderr,"| |_) | (_| | | (_| | | | | (_|  __/_|  _| | | | | |\n");
  fprintf(stderr,"|_.__/ \\__,_|_|\\__,_|_| |_|\\___\\___(_)_| |_| |_| |_|\n");

  fprintf(stderr, "  this is balance.fm %d.%d.%d\n", release, subrelease, patchlevel);
  fprintf(stderr, "  Copyright (c) 2000-2009,2010\n");
  fprintf(stderr, "  by Inlab Software GmbH, Gruenwald, Germany.\n");
  fprintf(stderr, "  All rights reserved.\n");
  fprintf(stderr, "\n");

  fprintf(stderr, "usage:\n");
  fprintf(stderr, "  balance.fm [-b addr] [-B addr] [-t sec] [-T sec]");
#if BALANCE_CAN_KEEPALIVE
  fprintf(stderr,                                                " [-k t,i,p] [-K t,i,p]");
#endif
  fprintf(stderr,                                                                      " [-adfpHM] \\\n");
  fprintf(stderr, "          port [h1[:p1[:maxc1]] [!%%] [ ... hN[:pN[:maxcN]]]]\n");
  fprintf(stderr, "  balance.fm [-b addr] -i [-d] port\n");
  fprintf(stderr, "  balance.fm [-b addr] -c cmd  [-d] port\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -a        enable channel autodisable option\n");
  fprintf(stderr, "  -b host   bind to specific address on listen\n");
  fprintf(stderr, "  -B host   bind to specific address for outgoing connections\n");
  fprintf(stderr, "  -c cmd    execute specified interactive command\n");
  fprintf(stderr, "  -d        debugging on\n");
  fprintf(stderr, "  -f        stay in foregound\n");
  fprintf(stderr, "  -i        interactive control\n");
#if BALANCE_CAN_KEEPALIVE
  fprintf(stderr, "  -k t,i,p  use client TCP keepalive (time, interval, # of probes)\n");
  fprintf(stderr, "  -K t,i,p  use server TCP keepalive (time, interval, # of probes)\n");
#endif
  fprintf(stderr, "  -H        failover even if Hash Type is used\n");
  fprintf(stderr, "  -M        use MMAP instead of SHM for IPC\n");
  fprintf(stderr, "  -p        packetdump\n");
  fprintf(stderr, "  -t sec    specify connect timeout in seconds (default=%d)\n", DEFAULTTIMEOUT);
  fprintf(stderr, "  -T sec    timeout (seconds) for select (0 => never) (default=%d)\n", DEFAULTSELTIMEOUT);
  fprintf(stderr, "   !        separates channelgroups (declaring previous to be Round Robin)\n");
  fprintf(stderr, "   %%        as !, but declaring previous group to be a Hash Type\n");

  fprintf(stderr, "\n");
  fprintf(stderr, "examples:\n");
  fprintf(stderr, "  balance.fm smtp mailhost1:smtp mailhost2:25 mailhost3\n");
  fprintf(stderr, "  balance.fm -i smtp\n");
  fprintf(stderr, "  balance.fm -b 2001:DB8::1 80 10.1.1.1 10.1.1.2\n");
  fprintf(stderr, "  balance.fm -b 2001:DB8::1 80\n");
  fprintf(stderr, "\n");

  exit(EX_USAGE);
}

// goto background:

static void background(void)
{
  int childpid;
  if ((childpid = fork()) < 0) {
    perror("fork");
    exit(EX_OSERR);
  } else {
    if (childpid > 0) {
      exit(EX_OK);              /* parent */
    }
  }
#ifdef BalanceBSD
  setpgid(getpid(), 0);
#else
  setpgrp();
#endif
  if(chdir("/") <0)
    perror("chdir");
  /* no more writing to stdout/stderr after this point, please */
  no_std_handles = 1;
  packetdump = 0;
  close(0);
  close(1);
  close(2);
}

static COMMON *makecommon(int argc, char **argv, int source_port)
{
  int i;
  int group;
  int channel;
  COMMON *mycommon;
  int numchannels = argc - 1;   // port number is first argument

  if (numchannels >= MAXCHANNELS) {
    log_msg(LOG_ERR, "MAXCHANNELS exceeded");
    exit(EX_USAGE);
  }

  if ((rendezvousfd = open(rendezvousfile, O_RDWR, 0)) < 0) {
    log_perror(LOG_ERR, "open");
    log_msg(LOG_ERR, "check rendezvousfile permissions [%s]", rendezvousfile);
    exit(EX_NOINPUT);
  }

  b_writelock();

  if ((mycommon =
       (COMMON *) shm_malloc(rendezvousfile, sizeof(COMMON))) == NULL) {
    log_msg(LOG_ERR, "cannot alloc COMMON struct");
    exit(EX_OSERR);
  }

  mycommon->pid = getpid();
  mycommon->release = release;
  mycommon->subrelease = subrelease;
  mycommon->patchlevel = patchlevel;
  mycommon->ngroups = 0;

  for (group = 0; group < MAXGROUPS; group++) {
    grp_nchannels(mycommon, group) = 0;
    grp_current(mycommon, group) = 0;
    grp_type(mycommon, group) = GROUP_RR;       // Default: RR
  }

  group = 0;
  channel = 0;

  for (i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "!")) {
      // This is a normal "GROUP_RR"-Type of Group
      if(channel <= 0) {
        err_dump("no channels in group");
      }
      grp_type(mycommon, group) = GROUP_RR;
      group++;
      channel = 0;
      if (group >= MAXGROUPS) {
        err_dump("too many groups");
      }
    } else if (!strcmp(argv[i], "%")) {
      // This is a "GROUP_HASH"
      if(channel <= 0) {
        err_dump("no channels in group");
      }
      grp_type(mycommon, group) = GROUP_HASH;
      group++;
      channel = 0;
      if (group >= MAXGROUPS) {
        err_dump("too many groups");
      }
    } else {
      chn_status(mycommon, group, channel) = 1;
      chn_c(mycommon, group, channel) = 0;      // connections...
      chn_tc(mycommon, group, channel) = 0;     // total connections...
      chn_maxc(mycommon, group, channel) = 0;   // maxconnections...
      setaddress(&chn_ipaddr(mycommon, group, channel),
                 &chn_port(mycommon, group, channel),
                 argv[i],
                 source_port, &chn_maxc(mycommon, group, channel));
      chn_bsent(mycommon, group, channel) = 0;
      chn_breceived(mycommon, group, channel) = 0;

      grp_nchannels(mycommon, group) += 1;
      channel++;
      if (channel >= MAXCHANNELS) {
        err_dump("too many channels in one group");
      }
    }
  }

  mycommon->ngroups = group + 1;

  if (debugflag && !no_std_handles) {
    fprintf(stderr, "the following channels are active:\n");
    for (group = 0; group < MAXGROUPS; group++) {
      for (i = 0; i < grp_nchannels(mycommon, group); i++) {
        fprintf(stderr, "%3d %2d %s:%d:%d\n",
                group,
                i,
                inet_ntoa(chn_ipaddr(mycommon, group, i)),
                chn_port(mycommon, group, i),
                chn_maxc(mycommon, group, i));
      }
    }
  }

  b_unlock();
  return (mycommon);
}

static int mycmp(const char *s1, const char *s2)
{
  int l;
  l = strlen(s1) < strlen(s2) ? strlen(s1) : strlen(s2);
  if (strlen(s1) > strlen(s2)) {
    return (!1);
  } else {
    return (!strncmp(s1, s2, l));
  }
}

static void shell(const char *argument)
{
  int i;
  int currentgroup = 0;
  char line[MAXINPUTLINE];
  char *command;

  // DJJ, Standing Cloud, Inc.
  //    In interactive mode, don't buffer stdout/stderr, so that
  //    other programs can operate balance through I/O streams
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  if (common->release == 0) {
    printf("no master process, exiting.\n");
    exit(EX_UNAVAILABLE);
  }

  if (common->release != release || common->subrelease != subrelease || common->patchlevel != patchlevel) {
    printf("release mismatch, expecting %d.%d.%d, got %d.%d.%d, exiting.\n",
           release, subrelease, patchlevel, common->release, common->subrelease, common->patchlevel);
    exit(EX_DATAERR);
  }

  if (kill(common->pid, SIGUSR1) == -1) {
    printf("no master process with pid %d, exiting.\n", common->pid);
    exit(EX_UNAVAILABLE);
  }

  if (argument == NULL) {
    printf("\nbalance.fm %d.%d.%d interactive command shell\n", release, subrelease, patchlevel);
    printf("PID of master process is %d\n\n", common->pid);
  }

  for (;;) {

    if (argument == NULL) {
      printf("balance.fm[%d] ", currentgroup);
      if (fgets(line, MAXINPUTLINE, stdin) == NULL) {
        printf("\n");
        exit(EX_OK);
      }
    } else {
      strncpy(line, argument, MAXINPUTLINE);
    }

    if ((command = strtok(line, " \t\n")) != NULL) {
      if (mycmp(command, "quit")) {
        exit(EX_OK);
      } else if (mycmp(command, "show")) {
        b_readlock();
        {
          int group;

          printf("%3s %4s %2s %3s %16s %5s %4s %11s %4s %11s %11s\n",
                 "GRP", "Type", "#", "S", "ip-address", "port", "c", "totalc",
                 "maxc", "sent", "rcvd");
          for (group = 0; group < MAXGROUPS; group++) {
            for (i = 0; i < grp_nchannels(common, group); i++) {
              printf("%3d %4s %2d %3s %16s %5d %4d %11u %4d %11llu %11llu\n",
                     group,
                     grp_type(common, group) == GROUP_RR ? "RR" : "Hash",
                     i,
                     chn_status(common, group, i) == 1 ? "ENA" : "dis",
                     inet_ntoa(chn_ipaddr(common, group, i)),
                     chn_port(common, group, i),
                     chn_c(common, group, i),
                     chn_tc(common, group, i),
                     chn_maxc(common, group, i),
                     chn_bsent(common, group, i),
                     chn_breceived(common, group, i)
                  );
            }
          }
        }
        b_unlock();
      } else if (mycmp(command, "help") || mycmp(command, "?")) {
        printf("available commands:\n");

        printf("  create <host> <port>           creates a channel in the current group\n");
        printf("  assign <channel> <host> <port> reassigns a channel in the current group\n");
        printf("  disable <channel>              disables specified channel in current group\n");
        printf("  enable <channel>               enables channel in current group\n");
        printf("  group <group>                  changes current group to <group>\n");
        printf("  hash                           sets distribution scheme of current group to Hash\n");
        printf("  help                           prints this message\n");
        printf("  kill                           kills master process and quits interactive mode\n");
        printf("  maxc <channel> <maxc>          specifies new maxc for channel of current group\n");
        printf("  mrtg-bytes <grp> <ch>          print bytes in/out in MRTG format\n");
        printf("  mrtg-conns <grp> <ch>          print total connections in MRTG format\n");
        printf("  quit                           quit interactive mode\n");
        printf("  reset <channel>                reset all counters of channel in current group\n");
        printf("  rr                             sets distribution scheme of current group to Round Robin\n");
        printf("  show                           show all channels in all groups\n");
        printf("  version                        show version id\n");

      } else if (mycmp(command, "kill")) {
        kill(common->pid, SIGKILL);
        sleep(1);
        if (kill(common->pid, SIGUSR1) == -1) {
          printf("shutdown complete, exiting.\n");
          common->release = 0;
          exit(EX_OK);
        } else {
          printf("shutdown failed.\n");
          exit(EX_UNAVAILABLE);
        }
      } else if (mycmp(command, "disable")) {
        char *arg;
        int n;
        if ((arg = strtok(NULL, " \t\n")) != NULL) {
          n = atoi(arg);
          if (n < 0 || n >= grp_nchannels(common, currentgroup)) {
            printf("no such channel %d\n", n);
          } else {
            c_writelock(currentgroup, n);
            if (chn_status(common, currentgroup, n) == 0) {
              printf("channel %d already disabled\n", n);
            } else {
              chn_status(common, currentgroup, n) = 0;
              printf("channel %d disabled\n", n);
            }
            c_unlock(currentgroup, n);
          }
        } else {
          printf("syntax error\n");
        }
      } else if (mycmp(command, "group")) {
        char *arg, n;
        if ((arg = strtok(NULL, " \t\n")) != NULL) {
          n = atoi(arg);
          if (n >= MAXGROUPS || n < 0) {
            printf("value out of range\n");
          } else {
            currentgroup = n;
          }
        } else {
          printf("syntax error\n");
        }

      } else if (mycmp(command, "reset")) {     // reset channel counters
        char *arg;
        int n;

        if ((arg = strtok(NULL, " \t\n")) != NULL) {
          n = atoi(arg);
          if (n < 0 || n >= grp_nchannels(common, currentgroup)) {
            printf("no such channel %d\n", n);
          } else {
            c_writelock(currentgroup, n);
            chn_breceived(common, currentgroup, n) = 0;
            chn_bsent(common, currentgroup, n) = 0;
            chn_tc(common, currentgroup, n) = 0;
            c_unlock(currentgroup, n);
            printf("channel %d counters reset\n", n);
          }
        } else {
          printf("syntax error\n");
        }

      } else if (mycmp(command, "enable")) {

        char *arg;
        int n;
        if ((arg = strtok(NULL, " \t\n")) != NULL) {
          n = atoi(arg);
          if (n < 0 || n >= grp_nchannels(common, currentgroup)) {
            printf("no such channel %d\n", n);
          } else {
            c_writelock(currentgroup, n);
            if (chn_status(common, currentgroup, n) == 1) {
              printf("channel %d already enabled\n", n);
            } else {
              chn_status(common, currentgroup, n) = 1;
              printf("channel %d enabled\n", n);
            }
            c_unlock(currentgroup, n);
          }
        } else {
          printf("syntax error\n");
        }

      } else if (mycmp(command, "create")) {
        char *arg1, *arg2;
        b_writelock();
        if (grp_nchannels(common, currentgroup) >= MAXCHANNELS) {
          printf("no channel slots available\n");
        } else {
          if ((arg1 = strtok(NULL, " \t\n")) != NULL) {
            if ((arg2 = strtok(NULL, " \t\n")) != NULL) {
              chn_status(common, currentgroup,
                         grp_nchannels(common, currentgroup)) = 0;
              if (setaddress_noexitonerror
                  (&chn_ipaddr
                   (common, currentgroup,
                    grp_nchannels(common, currentgroup)), &chn_port(common,
                                                                    currentgroup,
                                                                    grp_nchannels
                                                                    (common,
                                                                     currentgroup)),
                   arg1, getport(arg2))) {
                chn_bsent(common, currentgroup,
                          grp_nchannels(common, currentgroup)) = 0;
                chn_breceived(common, currentgroup,
                              grp_nchannels(common, currentgroup)) = 0;
                grp_nchannels(common, currentgroup)++;
                printf("channel created\n");
              } else {
                printf("invalid address\n");
              }
            } else {
              printf("syntax error\n");
            }
          } else {
            printf("syntax error\n");
          }
        }
        b_unlock();

    } else if (mycmp(command, "assign")) {
        char *arg1, *arg2, *arg3;

          if ((arg1 = strtok(NULL, " \t\n")) != NULL) {
        int chn = atoi(arg1);
            if (chn < 0 || chn >= MAXCHANNELS
                      || chn >= grp_nchannels(common, currentgroup)) {
               printf("unknown channel\n");
        } else {
            c_writelock(currentgroup, chn);
            if (chn_status(common, currentgroup, chn) != 0) {
               printf("channel must be disabled to assign new address\n");
            } else if ((arg2 = strtok(NULL, " \t\n")) != NULL) {
                if ((arg3 = strtok(NULL, " \t\n")) != NULL) {
                   if (setaddress_noexitonerror
                         (&chn_ipaddr(common, currentgroup, chn),
                          &chn_port(common, currentgroup, chn),
                          arg2, getport(arg3))) {
                       printf("channel reassigned\n");
                   } else {
                       printf("invalid address\n");
                   }
                } else {
                   printf("syntax error\n");
                }
            } else {
                printf("syntax error\n");
            }
            c_unlock(currentgroup, chn);
        }
      } else {
        printf("syntax error\n");
      }

    } else if (mycmp(command, "maxc")) {
        char *arg1, *arg2;
        b_writelock();
        if ((arg1 = strtok(NULL, " \t\n")) != NULL) {
          if ((arg2 = strtok(NULL, " \t\n")) != NULL) {
            if (atoi(arg1) < 0 || atoi(arg1) >= MAXCHANNELS
                || atoi(arg1) + 1 > grp_nchannels(common, currentgroup)) {
              printf("unknown channel\n");
            } else {
              chn_maxc(common, currentgroup, atoi(arg1)) = atoi(arg2);
              printf("maxc of channel %d changed to %d\n", atoi(arg1),
                     atoi(arg2));
            }
          } else {
            printf("syntax error\n");
          }
        } else {
          printf("syntax error\n");
        }
        b_unlock();

    } else if (mycmp(command, "mrtg-bytes")) {
        char *arg1, *arg2;
        int mygroup, mychannel;
        b_writelock();
        if ((arg1 = strtok(NULL, " \t\n")) != NULL) {
          if ((arg2 = strtok(NULL, " \t\n")) != NULL) {
            mygroup = atoi(arg1);
            mychannel = atoi(arg2);
            if (mygroup < 0 || mygroup >= MAXGROUPS) {
              printf("unknown group\n");
            } else {
              if(mychannel < 0 || mychannel > grp_nchannels(common, currentgroup)) {
                printf("unknown channel\n");
              } else {
                //
                printf("%llu\n", chn_breceived(common,mygroup,mychannel));
                printf("%llu\n", chn_bsent(common,mygroup,mychannel));
                printf("UNKNOWN\n");
                printf("group %d channel %d\n",mygroup, mychannel);
              }
            }
          } else {
            printf("syntax error\n");
          }
        } else {
          printf("syntax error\n");
        }
        b_unlock();

      } else if (mycmp(command, "mrtg-conns")) {
        char *arg1, *arg2;
        int mygroup, mychannel;
        b_writelock();
        if ((arg1 = strtok(NULL, " \t\n")) != NULL) {
          if ((arg2 = strtok(NULL, " \t\n")) != NULL) {
            mygroup = atoi(arg1);
            mychannel = atoi(arg2);
            if (mygroup < 0 || mygroup >= MAXGROUPS) {
              printf("unknown group\n");
            } else {
              if(mychannel < 0 || mychannel > grp_nchannels(common, currentgroup)) {
                printf("unknown channel\n");
              } else {
                //
                printf("%u\n", chn_tc(common,mygroup,mychannel));
                printf("UNKNOWN\n");
                printf("UNKNOWN\n");
                printf("group %d channel %d\n",mygroup, mychannel);
              }
            }
          } else {
            printf("syntax error\n");
          }
        } else {
          printf("syntax error\n");
        }
        b_unlock();

      } else if (mycmp(command, "version")) {
        printf("  This is balance.fm %d.%d.%d\n", release, subrelease, patchlevel);
        printf("  MAXGROUPS=%d\n", MAXGROUPS);
        printf("  MAXCHANNELS=%d\n", MAXCHANNELS);
      } else if (mycmp(command, "hash")) {
        b_writelock();
        grp_type(common, currentgroup) = GROUP_HASH;
        b_unlock();
        printf("group %d set to hash\n", currentgroup);

      } else if (mycmp(command, "rr")) {
        b_writelock();
        grp_type(common, currentgroup) = GROUP_RR;
        b_unlock();
        printf("group %d set to round robin\n", currentgroup);

      } else {
        printf("syntax error\n");
      }
      // printf("\n");
    }
    if (argument != NULL)
      exit(EX_OK);
  }
}

char bindhost_address[FILENAMELEN];

int main(int argc, char *argv[])
{
  int startindex;
  int sockfd, newsockfd, childpid;
  unsigned int clilen;
  int c;
  int source_port;
  int fd;
  char *argument = NULL;
  struct stat buffer;
  struct sockaddr_storage cli_addr;
  struct sigaction usr1_action, chld_action;
#ifdef BalanceBSD
#else
  struct rlimit r;
#endif

  connect_timeout = DEFAULTTIMEOUT;

  while ((c = getopt(argc, argv, "c:b:B:t:T:k:K:adfpiHM6")) != EOF) {
    switch (c) {
    case '6':
      bindipv6 = 1;
      break;
    case 'a':
      autodisable = 1;
      break;
    case 'b':
      bindhost = optarg;
      break;
    case 'B':
      outbindhost = optarg;
      break;
    case 'c':
      argument = optarg;
      interactive = 1;
      foreground = 1;
      packetdump = 0;
      break;
    case 't':
      connect_timeout = atoi(optarg);
      if (connect_timeout < 1) {
        usage();
      }
      break;
    case 'T':
      sel_tmout.tv_sec = atoi(optarg);
      sel_tmout.tv_usec = 0;
      if (sel_tmout.tv_sec < 1)
        usage();
      save_tmout = sel_tmout;
      break;
    case 'k':
    case 'K':
#if BALANCE_CAN_KEEPALIVE
      {
        KEEPALIVE *ka = c == 'k' ? &keepalive_client : &keepalive_server;
        char *p;
        ka->time = strtol(optarg, &p, 10);
        if (*p != ',' || ka->time <= 0)
          usage();
        ka->intvl = strtol(p + 1, &p, 10);
        if (*p != ',' || ka->intvl <= 0)
          usage();
        ka->probes = strtol(p + 1, &p, 10);
        if (*p != '\0' || ka->probes <= 0)
          usage();
      }
#else
      usage();
#endif
      break;
    case 'f':
      foreground = 1;
      break;
    case 'd':
      debugflag = 1;
      break;
    case 'p':
      packetdump = 1;
      break;
    case 'i':
      interactive = 1;
      foreground = 1;
      packetdump = 0;
      break;
    case 'H':
      hashfailover = 1;
      break;
    case 'M':
#ifdef  NO_MMAP
      fprintf(stderr, "Warning: Built without memory mapped file support, using IPC\n");
#else
      shmmapfile = 1;
#endif
      break;
    case '?':
    default:
      usage();
    }
  }

  debug("argv[0]=%s\n", argv[0]);
  debug("bindhost=%s\n", bindhost == NULL ? "NULL" : bindhost);

  if (interactive) {
    foreground = 1;
    packetdump = 0;
  }

  argc -= optind;
  argv += optind;

  if (!interactive) {
    if (argc < 1) {
      usage();
    }
  } else {
    if (argc != 1) {
      usage();
    }
  }
  usr1_action.sa_handler = usr1_handler;
  usr1_action.sa_flags = SA_RESTART;
  sigemptyset(&usr1_action.sa_mask);
  sigaction(SIGUSR1, &usr1_action, NULL);

  chld_action.sa_handler = chld_handler;
  chld_action.sa_flags = SA_RESTART;
  sigemptyset(&chld_action.sa_mask);
  sigaction(SIGCHLD, &chld_action, NULL);
  // really dump core if something fails...

#ifdef BalanceBSD
#else
  getrlimit(RLIMIT_CORE, &r);
  r.rlim_cur = r.rlim_max;
  setrlimit(RLIMIT_CORE, &r);
#endif

  // get the source port

  if ((source_port = getport(argv[0])) == 0) {
    fprintf(stderr, "invalid port [%s], exiting.\n", argv[0]);
    exit(EX_USAGE);
  }

  debug("source port %d\n", source_port);

  /*
   * Bind our local address so that the client can send to us.
   * Handling of -b option.
   */

  if (bindhost != NULL) {
    snprintf(bindhost_address, FILENAMELEN, "%s", bindhost);
  } else {
    snprintf(bindhost_address, FILENAMELEN, "%s", "0.0.0.0");
  }

  stat(SHMDIR, &buffer);
  if (!S_ISDIR(buffer.st_mode)) {
    mode_t old = umask(0);
    if (mkdir(SHMDIR, 01777) < 0) {
      if(errno != EEXIST) {
        fprintf(stderr, "ERROR: rendezvous directory not available and/or creatable\n");
        fprintf(stderr, "       please create %s with mode 01777 like this: \n", SHMDIR);
        fprintf(stderr, "       # mkdir -m 01777 %s\n", SHMDIR);
        umask(old);
        exit(EX_UNAVAILABLE);
      }
    }
    umask(old);
  }

  sprintf(rendezvousfile, "%sbalance.%d.%s", SHMDIR, source_port,
          bindhost_address);

  if (stat(rendezvousfile, &buffer) == -1) {
    // File not existing yet ...
    if ((fd = open(rendezvousfile, O_CREAT | O_RDWR, 0666)) == -1) {
      fprintf(stderr, "cannot create rendezvous file %s\n",
              rendezvousfile);
      exit(EX_OSERR);
    } else {
      debug("file %s created\n", rendezvousfile);
      close(fd);
    }
  } else {
    debug("file %s already exists\n", rendezvousfile);
  }

  if (interactive) {
    // command mode !
    if ((rendezvousfd = open(rendezvousfile, O_RDWR, 0)) < 0) {
      perror("open");
      fprintf(stderr, "check rendezvousfile permissions [%s]\n", rendezvousfile);
      exit(EX_OSERR);
    }
    if ((common =
         (COMMON *) shm_malloc(rendezvousfile, sizeof(COMMON))) == NULL) {
      fprintf(stderr, "cannot alloc COMMON struct\n");
      exit(EX_OSERR);
    }
    shell(argument);
  }

  openlog("Balance.fm", LOG_ODELAY | LOG_PID | LOG_CONS, LOG_DAEMON);

  /*  Open a TCP socket (an Internet stream socket). */

  sockfd = create_serversocket(bindhost, argv[0]);

  (void) setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &sockbufsize, sizeof(sockbufsize));
  (void) setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &sockbufsize, sizeof(sockbufsize));

  // init of common (*after* bind())

  if (!foreground) {
    background();
  }

  common = makecommon(argc, argv, source_port);

  for (;;) {
    int index;
    unsigned int uindex;
    int groupindex = 0;         // always start at groupindex 0

    clilen = sizeof(cli_addr);

    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if (newsockfd < 0) {
      log_perror(LOG_INFO, "accept");
      continue;
    }

    if (debugflag && !no_std_handles) {
      char buf[1024];
      inet_ntop(AF_INET6,&(((struct sockaddr_in6*) &cli_addr)->sin6_addr),buf,1024);
      fprintf(stderr, "connect from %s clilen=%d\n", buf, clilen);
    }

    /*
     * the balancing itself:
     * - groupindex = 0
     * - decision wich channel to use for the first try
     * - client address available in cli_addr
     *
     */

    b_writelock();
    for (;;) {
      index = grp_current(common, groupindex);
      for (;;) {
        if (grp_type(common, groupindex) == GROUP_RR) {
          if (chn_status(common, groupindex, index) == 1 &&
              (chn_maxc(common, groupindex, index) == 0 ||
               (chn_c(common, groupindex, index) <
                chn_maxc(common, groupindex, index)))) {
            break;              // channel found
          } else {
            index++;
            if (index >= grp_nchannels(common, groupindex)) {
              index = 0;
            }
            if (index == grp_current(common, groupindex)) {
              index = -1;       // no channel available in this group
              break;
            }
          }
        } else if (grp_type(common, groupindex) == GROUP_HASH) {
          uindex = hash_fold(&(((struct sockaddr_in6 *) &cli_addr)->sin6_addr), clilen);

          debug("HASH-method: fold returns %u\n", uindex);

          index = uindex % grp_nchannels(common, groupindex);
          debug("modulo %d gives %d\n", grp_nchannels(common, groupindex), index);
          if (chn_status(common, groupindex, index) == 1
              && (chn_maxc(common, groupindex, index) == 0
                  || (chn_c(common, groupindex, index) <
                      chn_maxc(common, groupindex, index)))
              ) {
            break;              // channel found, channel valid for HASH
          } else {
            if (hashfailover == 1) {
              // if failover even if hash: try next channel in this group.
              debug("channel disabled - hashfailover.\n");
              startindex = index;
              for (;;) {
                index++;
                if (index >= grp_nchannels(common, groupindex)) {
                  index = 0;
                }
                if (index == startindex) {
                  debug("no valid channel in group %d.\n", groupindex);
                  index = -1;
                  break;
                }
                if (chn_status(common, groupindex, index) == 1 &&
                    (chn_maxc(common, groupindex, index) == 0 ||
                     (chn_c(common, groupindex, index) <
                      chn_maxc(common, groupindex, index)))
                    ) {
                  debug("channel choosen: %d in group %d.\n", index, groupindex);
                  break;        // channel found
                }
              }

            } else {
              debug("no valid channel in group %d. Failover?\n", groupindex);
              index = -1;
            }
            break;
          }
        } else {
          err_dump("PANIC: invalid group type");
        }
      }

      // Hier fallen wir "raus" mit dem index in der momentanen Gruppe, oder -1
      // wenn nicht moeglich in dieser Gruppe

      grp_current(common, groupindex) = index;
      grp_current(common, groupindex)++;        // current index dieser gruppe wieder null, wenn vorher ungueltig (-1)

      // Der index der gruppe wird neu berechnet und gespeichert, "index" ist immer noch
      // -1 oder der zu waehlende index...

      if (grp_current(common, groupindex) >=
          grp_nchannels(common, groupindex)) {
        grp_current(common, groupindex) = 0;
      }

      if (index >= 0) {
        chn_c(common, groupindex, index)++;     // we promise a successful connection
        chn_tc(common, groupindex, index)++;    // also incrementing the total count
        // c++
        break;                                  // index in this group found
      } else {
        groupindex++;                           // try next group !
        if (groupindex >= MAXGROUPS) {
          break;                                // end of groups...
        }
      }
    }

    b_unlock();

    if (index >= 0) {
      if ((childpid = fork()) < 0) {

        // the connection is rejected if fork() returns error,
        // but main process stays alive !

        log_perror(LOG_INFO, "fork");
      } else if (childpid == 0) {       // child process
        close(sockfd);                  // close original socket
        // process the request:

        stream(newsockfd, groupindex, index, &cli_addr, clilen);
        exit(EX_OK);
      }
    }

    close(newsockfd);           // parent process
  }
}
