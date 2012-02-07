/*
 * Copyright (c) 2000-2004,2005 by Inlab Software GmbH, Gruenwald, Germany.
 * All rights reserved.
 *
 */

/*
 * $Id: butils.c,v 1.1 2010/01/29 10:40:16 t Exp $
 */

#include <balance.h>

char* butils_rcsid="$Id: butils.c,v 1.1 2010/01/29 10:40:16 t Exp $";

unsigned int hash_fold(char* s, int len)
{
  unsigned int rc = 0;
  int i;
  for (i=0; i<len; i++) {
    rc = s[i] + 31 * rc;
  }

  return(rc);
}

ssize_t writen(int fd, unsigned char *ptr, size_t nbytes)
{
  int nleft;
  ssize_t nwritten;

  nleft = nbytes;

  while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if (nwritten <= 0) {
      return (nwritten);        /* error */
    }
    nleft -= nwritten;
    ptr += nwritten;
  }

  return (nbytes - nleft);
}
