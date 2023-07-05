#ifndef _CRT_LIB_SUPPORT_
#define _CRT_LIB_SUPPORT_

#include "base.h"

// Base.h

///
/// Undeclared type.
///
#define VOID      void
///
/// NULL pointer (VOID *)
///
#define NULL  ((VOID *) 0)

// TBD: enable
// #define OPENSSLDIR ""
// #define ENGINESDIR ""

#ifndef THIRTY_TWO_BIT
#define THIRTY_TWO_BIT
#endif

//
// We already have "no-ui" in out Configure invocation.
// but the code still fails to compile.
// Ref:  https://github.com/openssl/openssl/issues/8904
//
// This is defined in CRT library(stdio.h).
//
#ifndef BUFSIZ
#define BUFSIZ  8192
#endif

//
// Definitions for global constants used by CRT library routines
//
#define EINVAL       22               /* Invalid argument */
#define EAFNOSUPPORT 47               /* Address family not supported by protocol family */
#define INT_MAX      0x7FFFFFFF       /* Maximum (signed) int value */
#define LONG_MAX     0X7FFFFFFFL      /* max value for a long */
#define LONG_MIN     (-LONG_MAX-1)    /* min value for a long */
#define ULONG_MAX    0xFFFFFFFF       /* Maximum unsigned long value */
#define CHAR_BIT     8                /* Number of bits in a char */

//
// Address families.
//
#define AF_INET   2     /* internetwork: UDP, TCP, etc. */
#define AF_INET6  24    /* IP version 6 */

//
// Define constants based on RFC0883, RFC1034, RFC 1035
//
#define NS_INT16SZ    2   /*%< #/bytes of data in a u_int16_t */
#define NS_INADDRSZ   4   /*%< IPv4 T_A */
#define NS_IN6ADDRSZ  16  /*%< IPv6 T_AAAA */

//
// Basic types mapping
//
typedef UINTN          size_t;
typedef UINTN          u_int;
typedef INTN           ptrdiff_t;
typedef INTN           ssize_t;
typedef INT32          time_t;
typedef UINT8          __uint8_t;
typedef UINT8          sa_family_t;
typedef UINT8          u_char;
typedef UINT32         uid_t;
typedef UINT32         gid_t;
typedef CHAR16         wchar_t;

//
// File operations are not required for EFI building,
// so FILE is mapped to VOID * to pass build
//
typedef VOID  *FILE;

//
// Structures Definitions
//
struct tm {
  int   tm_sec;     /* seconds after the minute [0-60] */
  int   tm_min;     /* minutes after the hour [0-59] */
  int   tm_hour;    /* hours since midnight [0-23] */
  int   tm_mday;    /* day of the month [1-31] */
  int   tm_mon;     /* months since January [0-11] */
  int   tm_year;    /* years since 1900 */
  int   tm_wday;    /* days since Sunday [0-6] */
  int   tm_yday;    /* days since January 1 [0-365] */
  int   tm_isdst;   /* Daylight Savings Time flag */
  long  tm_gmtoff;  /* offset from CUT in seconds */
  char  *tm_zone;   /* timezone abbreviation */
};

struct timeval {
  long tv_sec;      /* time value, in seconds */
  long tv_usec;     /* time value, in microseconds */
};

struct sockaddr {
  __uint8_t    sa_len;       /* total length */
  sa_family_t  sa_family;    /* address family */
  char         sa_data[14];  /* actually longer; address value */
};

//
// Global variables
//
extern int  errno;
extern FILE *stderr;

//
// Function prototypes of CRT Library routines
//
void           *malloc     (size_t);
void           *realloc    (void *, size_t);
void           free        (void *);
void           *memset     (void *, int, size_t);
int            memcmp      (const void *, const void *, size_t);
int            isdigit     (int);
int            isspace     (int);
int            isxdigit    (int);
int            isalnum     (int);
int            isupper     (int);
int            tolower     (int);
int            strcmp      (const char *, const char *);
int            strncasecmp (const char *, const char *, size_t);
char           *strchr     (const char *, int);
char           *strrchr    (const char *, int);
unsigned long  strtoul     (const char *, char **, int);
long           strtol      (const char *, char **, int);
char           *strerror   (int);
size_t         strspn      (const char *, const char *);
size_t         strcspn     (const char *, const char *);
int            printf      (const char *, ...);
int            sscanf      (const char *, const char *, ...);
FILE           *fopen      (const char *, const char *);
size_t         fread       (void *, size_t, size_t, FILE *);
size_t         fwrite      (const void *, size_t, size_t, FILE *);
int            fclose      (FILE *);
int            fprintf     (FILE *, const char *, ...);
time_t         time        (time_t *);
struct tm      *gmtime     (const time_t *);
uid_t          getuid      (void);
uid_t          geteuid     (void);
gid_t          getgid      (void);
gid_t          getegid     (void);
int            issetugid   (void);
void           qsort       (void *, size_t, size_t, int (*)(const void *, const void *));
char           *getenv     (const char *);
char           *secure_getenv (const char *);
#if defined(__GNUC__) && (__GNUC__ >= 2)
void           abort       (void) __attribute__((__noreturn__));
#else
void           abort       (void);
#endif
int            inet_pton   (int, const char *, void *);

typedef __builtin_va_list va_list;
#define va_start(ap, param) __builtin_va_start(ap, param)
#define va_end(ap)          __builtin_va_end(ap)
#define va_arg(ap, type)    __builtin_va_arg(ap, type)

//
void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *vl, const void *vr, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memchr(const void *, int, size_t);

size_t strlen(const char *);

int strcmp(const char *, const char *);
int strncmp(const char *, const char *, size_t);

char *strcat(char *, const char *);
char *strncat(char *, const char *, size_t);

char *strcpy(char *, const char *);
char *strncpy(char *, const char *, size_t);

char *strchr(const char *, int);
char *strrchr(const char *, int);

char *strstr(const char *, const char *);

size_t strcspn(const char *s, const char *c);
size_t strspn(const char *s, const char *c);

int strcasecmp (const char *, const char *);
int strncasecmp (const char *, const char *, size_t);

void *memset(void *, int, size_t);
void *memcpy(void *, const void *, size_t);
int memcmp(const void *vl, const void *vr, size_t n);
void *memmove(void *dest, const void *src, size_t n);
void *memchr(const void *, int, size_t);

int atoi(const char *s);

#define offsetof(TYPE, Field) ((UINTN) &(((TYPE *)0)->Field))

//
//  Macros that directly disable unused functions
//
#ifndef setbuf
#define setbuf(x,y)
#endif

#ifndef stat
#define stat(a,b) -1
#endif

//
// Global variables
//
extern int  errno;
extern FILE *stderr;

//
// Assert
//
#ifndef assert
#define assert(x) ((void)((x) || (__assert_fail(#x, __FILE__, __LINE__, __func__),0)))
void __assert_fail (const char *, const char *, int, const char *);
#endif

//
// For loader_file.c
//
struct stat {
  UINT32 st_mode;
};
#define S_IFMT  0170000
#define S_IFDIR 0040000
#define S_ISDIR(mode)  (((mode) & S_IFMT) == S_IFDIR)


#endif