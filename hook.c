#include "hook.h"
#include "_cgo_export.h"

uc_err hook_add(uc_engine *uc, uc_hook *hh, int type, void *data, uint64_t begin, uint64_t end) {
    void *callback;
    switch (type) {
    case UC_HOOK_INTR:
        callback = &hookInterruptWrap;
        break;
    case UC_HOOK_INSN_INVALID:
        callback = &hookInvalidWrap;
        break;
    case UC_HOOK_CODE:
    case UC_HOOK_BLOCK:
        callback = &hookCodeWrap;
        break;
    default:
        if ((type & (UC_HOOK_MEM_INVALID | UC_HOOK_MEM_VALID | UC_HOOK_MEM_READ_AFTER)) == 0)
            return UC_ERR_HOOK;
        callback = &hookMemoryWrap;
        break;
    }
    return uc_hook_add(uc, hh, type, callback, data, begin, end);
}