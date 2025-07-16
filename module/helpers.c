#include <linux/slab.h>    // for kmalloc and kfree
#include "helpers.h"

char* print_hi(void) {
    char *msg = kmalloc(48, GFP_KERNEL);
    if (!msg)
        return NULL;

    strcpy(msg, "HIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII");
    return msg;
}