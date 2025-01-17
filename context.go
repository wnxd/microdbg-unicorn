package unicorn

import (
	"unsafe"

	"github.com/wnxd/microdbg/emulator"
)

// #include "unicorn/unicorn.h"
import "C"

type context struct {
	u      *unicorn
	handle *C.uc_context
}

func (ctx *context) Close() error {
	return errCheck(C.uc_context_free(ctx.handle))
}

func (ctx *context) Save() error {
	return errCheck(C.uc_context_save(ctx.u.handle, ctx.handle))
}

func (ctx *context) Restore() error {
	return errCheck(C.uc_context_restore(ctx.u.handle, ctx.handle))
}

func (ctx *context) RegRead(reg emulator.Reg) (uint64, error) {
	var value uint64
	return value, ctx.RegReadPtr(reg, unsafe.Pointer(&value))
}

func (ctx *context) RegWrite(reg emulator.Reg, value uint64) error {
	return ctx.RegWritePtr(reg, unsafe.Pointer(&value))
}

func (ctx *context) RegReadPtr(reg emulator.Reg, ptr unsafe.Pointer) error {
	return errCheck(C.uc_context_reg_read(ctx.handle, C.int(reg), ptr))
}

func (ctx *context) RegWritePtr(reg emulator.Reg, ptr unsafe.Pointer) error {
	return errCheck(C.uc_context_reg_write(ctx.handle, C.int(reg), ptr))
}

func (ctx *context) RegReadBatch(regs ...emulator.Reg) ([]uint64, error) {
	if len(regs) == 0 {
		return nil, nil
	}
	cregs := make([]C.int, len(regs))
	for i, v := range regs {
		cregs[i] = C.int(v)
	}
	vals := make([]uint64, len(regs))
	cvals := make([]uintptr, len(regs))
	for i := 0; i < len(regs); i++ {
		cvals[i] = uintptr(unsafe.Pointer(&vals[i]))
	}
	return vals, errCheck(C.uc_context_reg_read_batch(ctx.handle, unsafe.SliceData(cregs), (*unsafe.Pointer)(unsafe.Pointer(unsafe.SliceData(cvals))), C.int(len(regs))))
}

func (ctx *context) RegWriteBatch(regs []emulator.Reg, vals []uint64) error {
	size := min(len(regs), len(vals))
	if size == 0 {
		return nil
	}
	cregs := make([]C.int, size)
	for i, v := range regs[:size] {
		cregs[i] = C.int(v)
	}
	cvals := make([]uintptr, size)
	for i := 0; i < size; i++ {
		cvals[i] = uintptr(unsafe.Pointer(&vals[i]))
	}
	return errCheck(C.uc_context_reg_write_batch(ctx.handle, unsafe.SliceData(cregs), (*unsafe.Pointer)(unsafe.Pointer(unsafe.SliceData(cvals))), C.int(len(regs))))
}

func (ctx *context) Clone() (emulator.Context, error) {
	clone, err := ctx.u.ContextAlloc()
	if err != nil {
		return nil, err
	}
	size := C.uc_context_size(ctx.u.handle)
	copy(unsafe.Slice((*byte)(unsafe.Pointer(clone.(*context).handle)), size), unsafe.Slice((*byte)(unsafe.Pointer(ctx.handle)), size))
	return clone, nil
}

func (u *unicorn) ContextAlloc() (emulator.Context, error) {
	var handle *C.uc_context
	err := errCheck(C.uc_context_alloc(u.handle, &handle))
	if err != nil {
		return nil, err
	}
	ctx := &context{u: u, handle: handle}
	return ctx, nil
}
