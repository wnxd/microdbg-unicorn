#include "uc.h"

uc_err mem_write(uc_engine *uc, uint64_t address, uintptr_t bytes, size_t size)
{
    return uc_mem_write(uc, address, (void *)bytes, size);
}

uc_err mem_read(uc_engine *uc, uint64_t address, uintptr_t bytes, size_t size)
{
    return uc_mem_read(uc, address, (void *)bytes, size);
}