/*
 * Copyright (c) 2000-2004,2005 by Inlab Software GmbH, Gruenwald, Germany.
 * All rights reserved.
 *
 */

/*
 * $Id: butils.c,v 1.1 2010/01/29 10:40:16 t Exp $
 */

#include "balance.h"

unsigned int hash_fold(const void *ptr, int len)
{
  const unsigned char *s = ptr;
  unsigned int rc = 0;

  for (int i = 0; i < len; i++) {
    rc = s[i] + 31 * rc;
  }

  return rc;
}

ssize_t writen(int fd, const unsigned char *ptr, size_t nbytes)
{
  int nleft;
  ssize_t nwritten;

  nleft = nbytes;

  while (nleft > 0) {
    nwritten = write(fd, ptr, nleft);
    if (nwritten <= 0) {
      return nwritten;        /* error */
    }
    nleft -= nwritten;
    ptr += nwritten;
  }

  return nbytes - nleft;
}

static void *safe_malloc(size_t size)
{
  void *m = malloc(size);
  if (m == NULL) {
    err_dump("out of memory");
  }
  return m;
}

static void *safe_realloc(void *ptr, size_t size)
{
  void *m = realloc(ptr, size);
  if (size > 0 && m == NULL) {
    err_dump("out of memory");
  }
  return m;
}

static char *get_token(const char **str, const char *delim_list)
{
  const char *p = *str;
  char *token = safe_malloc(strlen(p) + 1);
  char *t = token;

  while (*p) {
    const char *d = delim_list;

    while (*p && *p == '\\') {
      if (*++p) {
        switch (*p) {
          case 'a': *t++ = '\a'; break;
          case 'b': *t++ = '\b'; break;
          case 't': *t++ = '\t'; break;
          case 'n': *t++ = '\n'; break;
          case 'v': *t++ = '\v'; break;
          case 'f': *t++ = '\f'; break;
          case 'r': *t++ = '\r'; break;
          default:  *t++ = *p;   break;
        }

        p++;
      }
    }

    while (*p && *d && *p != *d) {
      d++;
    }

    if (*p == '\0' || *p == *d) {
      break;
    }

    *t++ = *p++;
  }

  *str = p;
  *t++ = '\0';

  return safe_realloc(token, t - token);
}

static struct monitor_action *append_action(struct monitor_action ***pppma, enum monitor_action_type type)
{
  struct monitor_action *ma = safe_malloc(sizeof(struct monitor_action));
  ma->type = type;
  ma->next = **pppma;
  **pppma = ma;
  *pppma = &ma->next;
  return ma;
}

struct monitor_spec *monitor_spec_parse(const char *str, const struct monitor_defaults *defaults)
{
  struct monitor_spec *ms = safe_malloc(sizeof(struct monitor_spec));

  ms->action_list = NULL;
  ms->interval = DEFAULT_MON_INTERVAL;
  ms->enable = true;
  ms->disable = true;

  struct monitor_action **ppma = &ms->action_list;
  struct monitor_action *cur_ma = NULL;

  while (*str) {
    char *k = get_token(&str, ":=");
    char *v = NULL;

    if (*str == '=') {
      str++;
      v = get_token(&str, ":");
    }

    if (strcmp(k, "connect") == 0) {
      if (v) {
        err_dump("unexpected value for 'connect'");
      }
      cur_ma = append_action(&ppma, MA_CONNECT);
      cur_ma->u.connect.timeout = defaults->connect_timeout;
    } else if (strcmp(k, "command") == 0) {
      if (v == NULL) {
        err_dump("'command' action requires a value");
      }
      cur_ma = append_action(&ppma, MA_COMMAND);
      cur_ma->u.command.cmdline = v;
      cur_ma->u.command.num_pass = 1;
      cur_ma->u.command.pass = safe_malloc(sizeof(int));
      cur_ma->u.command.pass[0] = 0;
    } else if (strcmp(k, "interval") == 0) {
      if (v == NULL) {
        err_dump("'interval' option requires a value");
      }
      char *end;
      ms->interval = strtol(v, &end, 0);
      if (*end || ms->interval <= 0) {
        err_dump("error parsing interval");
      }
      free(v);
    } else if (strcmp(k, "timeout") == 0) {
      if (v == NULL) {
        err_dump("'timeout' option requires a value");
      }
      if (cur_ma == NULL) {
        err_dump("'timeout' option given without action");
      }
      if (cur_ma->type != MA_CONNECT) {
        err_dump("'timeout' option unsupported for this action");
      }
      char *end;
      cur_ma->u.connect.timeout = strtod(v, &end);
      if (*end) {
        err_dump("error parsing timeout");
      }
      if (cur_ma->u.connect.timeout < 1e-3f || cur_ma->u.connect.timeout > 60.0f) {
        err_dump("timeout outside of supported range");
      }
      free(v);
    } else if (strcmp(k, "pass") == 0) {
      if (v == NULL) {
        err_dump("'pass' option requires a value");
      }
      if (cur_ma == NULL) {
        err_dump("'pass' option given without action");
      }
      if (cur_ma->type != MA_COMMAND) {
        err_dump("'pass' option unsupported for this action");
      }
      cur_ma->u.command.num_pass = 1;
      for (const char *c = v; *c; c++) {
        if (*c == ',') {
          cur_ma->u.command.num_pass++;
        }
      }
      cur_ma->u.command.pass = safe_realloc(cur_ma->u.command.pass,
                                            cur_ma->u.command.num_pass*sizeof(int));
      char *end = v;
      for (size_t i = 0; i < cur_ma->u.command.num_pass; i++) {
        cur_ma->u.command.pass[i] = strtol(end, &end, 0);
        if (*end != (i < cur_ma->u.command.num_pass - 1 ? ',' : '\0')) {
          err_dump("error parsing pass value list");
        }
        if (*end) {
          end++;
        }
      }
      free(v);
    } else if (strcmp(k, "noenable") == 0) {
      if (v) {
        err_dump("unexpected value for 'noenable'");
      }
      ms->enable = false;
    } else if (strcmp(k, "nodisable") == 0) {
      if (v) {
        err_dump("unexpected value for 'nodisable'");
      }
      ms->disable = false;
    } else {
      err_dump("invalid monitoring spec");
    }

    free(k);

    if (*str) {
      str++;
    }
  }

  return ms;
}

void monitor_spec_free(struct monitor_spec *spec)
{
  if (spec)
  {
    struct monitor_action *ma = spec->action_list;

    while (ma) {
      switch (ma->type) {
        case MA_COMMAND:
          free(ma->u.command.cmdline);
          free(ma->u.command.pass);
          break;
        default:
          break;
      }
      struct monitor_action *d = ma;
      ma = ma->next;
      free(d);
    }

    free(spec);
  }
}

void monitor_spec_dump(FILE *fh, const struct monitor_spec *spec)
{
  if (spec)
  {
    fprintf(fh, "monitoring setup:\n");
    fprintf(fh, "  check interval: %d seconds\n", spec->interval);
    fprintf(fh, "  channels will %sbe automatically enabled\n", spec->enable ? "" : "not ");
    fprintf(fh, "  channels will %sbe automatically disabled\n", spec->disable ? "" : "not ");

    const struct monitor_action *ma = spec->action_list;

    fprintf(fh, "  checks:%s\n", ma ? "" : " none");

    while (ma) {
      switch (ma->type) {
        case MA_CONNECT:
          fprintf(fh, "    - connect to channel host [timeout: %.2fs]\n", ma->u.connect.timeout);
          break;
        case MA_COMMAND:
          fprintf(fh, "    - run command: %s [pass exit code%s: ",
                      ma->u.command.cmdline, ma->u.command.num_pass > 1 ? "s" : "");
          for (size_t i = 0; i < ma->u.command.num_pass; i++) {
            fprintf(fh, "%s%d", i == 0 ? "" : ", ", ma->u.command.pass[i]);
          }
          fprintf(fh, "]\n");
          break;
        default:
          break;
      }

      ma = ma->next;
    }
  }
}

static int command_format(char *buffer, int buflen, const char *format, const char *host, int port)
{
  int len = 0;
  char portbuf[32];
  sprintf(portbuf, "%d", port);

#define APPEND_C(c)                            \
        do {                                   \
          if (buffer && len < buflen) {        \
            buffer[len] = (c);                 \
          }                                    \
          len++;                               \
        } while (0)

#define APPEND_S(s)                            \
        do {                                   \
          const char *scp = (s);               \
          int sl = strlen(scp);                \
          if (buffer && len < buflen) {        \
            int cp = buflen - len;             \
            if (sl < cp) cp = sl;              \
            strncpy(buffer + len, (scp), cp);  \
          }                                    \
          len += sl;                           \
        } while (0)

  for (const char *f = format; *f; f++) {
    if (*f == '%' && f[1]) {
      switch (*++f) {
        case 'H':
          APPEND_S(host);
          break;
        case 'P':
          APPEND_S(portbuf);
          break;
        case '%':
           APPEND_C('%');
           break;
        default:
           APPEND_C('%');
           APPEND_C(*f);
           break;
      }
    } else {
      APPEND_C(*f);
    }
  }

  APPEND_C('\0');

#undef APPEND_C
#undef APPEND_S

  return len;
}

char *monitor_command_format(const char *format, const char *host, int port)
{
  int len = command_format(NULL, 0, format, host, port);
  char *buf = safe_malloc(len);
  command_format(buf, len, format, host, port);
  return buf;
}
