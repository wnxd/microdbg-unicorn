#ifndef UC_H
#define UC_H

#include "unicorn/unicorn.h"

uc_err mem_write(uc_engine *uc, uint64_t address, uintptr_t bytes, size_t size);
uc_err mem_read(uc_engine *uc, uint64_t address, uintptr_t bytes, size_t size);

#endif