package unicorn

//#include "hook.h"
import "C"

import (
	"unsafe"

	"github.com/wnxd/microdbg/emulator"
)

type hookData struct {
	uc       *C.uc_engine
	handler  C.uc_hook
	typ      emulator.HookType
	callback any
	data     any
}

func (h *hookData) Close() error {
	return errCheck(C.uc_hook_del(h.uc, h.handler))
}

func (h *hookData) Type() emulator.HookType {
	return h.typ
}

//export hookInterruptWrap
func hookInterruptWrap(_ unsafe.Pointer, intno uint32, data unsafe.Pointer) {
	hook := (*hookData)(data)
	hook.callback.(emulator.InterruptCallback)(uint64(intno), hook.data)
}

//export hookInvalidWrap
func hookInvalidWrap(_ unsafe.Pointer, data unsafe.Pointer) bool {
	hook := (*hookData)(data)
	return hook.callback.(emulator.InvalidCallback)(hook.data)
}

//export hookCodeWrap
func hookCodeWrap(_ unsafe.Pointer, addr uint64, size uint32, data unsafe.Pointer) {
	hook := (*hookData)(data)
	hook.callback.(emulator.CodeCallback)(addr, uint64(size), hook.data)
}

//export hookMemoryWrap
func hookMemoryWrap(_ unsafe.Pointer, typ C.uc_mem_type, addr uint64, size int32, value uint64, data unsafe.Pointer) bool {
	var hookType emulator.HookType
	switch typ {
	case C.UC_MEM_READ:
		hookType = emulator.HOOK_TYPE_MEM_READ
	case C.UC_MEM_WRITE:
		hookType = emulator.HOOK_TYPE_MEM_WRITE
	case C.UC_MEM_FETCH:
		hookType = emulator.HOOK_TYPE_MEM_FETCH
	case C.UC_MEM_READ_UNMAPPED:
		hookType = emulator.HOOK_TYPE_MEM_READ_UNMAPPED
	case C.UC_MEM_WRITE_UNMAPPED:
		hookType = emulator.HOOK_TYPE_MEM_WRITE_UNMAPPED
	case C.UC_MEM_FETCH_UNMAPPED:
		hookType = emulator.HOOK_TYPE_MEM_FETCH_UNMAPPED
	case C.UC_MEM_READ_PROT:
		hookType = emulator.HOOK_TYPE_MEM_READ_PROT
	case C.UC_MEM_WRITE_PROT:
		hookType = emulator.HOOK_TYPE_MEM_WRITE_PROT
	case C.UC_MEM_FETCH_PROT:
		hookType = emulator.HOOK_TYPE_MEM_FETCH_PROT
	case C.UC_MEM_READ_AFTER:
		hookType = emulator.HOOK_TYPE_MEM_READ_AFTER
	}
	hook := (*hookData)(data)
	return hook.callback.(emulator.MemoryCallback)(hookType, addr, uint64(size), value, hook.data)
}

func (u *unicorn) Hook(typ emulator.HookType, callback any, data any, begin, end uint64) (emulator.Hook, error) {
	var hookType C.int
	if typ == emulator.HOOK_TYPE_INSN_INVALID {
		hookType = C.UC_HOOK_INSN_INVALID
	} else {
		hookType = C.int(typ)
	}
	hook := new(hookData)
	err := errCheck(C.hook_add(u.handle, &hook.handler, hookType, unsafe.Pointer(hook), C.uint64_t(begin), C.uint64_t(end)))
	if err != nil {
		return nil, err
	}
	hook.uc = u.handle
	hook.typ = typ
	hook.callback = callback
	hook.data = data
	return hook, nil
}
