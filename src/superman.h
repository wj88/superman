#ifndef __SUPERMAN__
#define __SUPERMAN__

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>

// Use a test protocol number
#define SUPERMAN_PROTOCOL_NUM 253

// Comment the next line if local comms should not be encrypted
#define ENCRYPT_LOCAL

#else

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#endif

#define SUPERMAN_VERSION_MAJOR 1
#define SUPERMAN_VERSION_MINOR 0

#endif
