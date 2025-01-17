#ifndef HOOK_H
#define HOOK_H

#include "unicorn/unicorn.h"

uc_err hook_add(uc_engine *uc, uc_hook *hh, int type, void *data, uint64_t begin, uint64_t end);

#endif