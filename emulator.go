package unicorn

import (
	"unsafe"

	"github.com/wnxd/microdbg/emulator"
)

/*
#cgo CFLAGS: -O3
#cgo LDFLAGS: -lunicorn
#cgo linux LDFLAGS: -lrt
#include "uc.h"
*/
import "C"

type unicorn struct {
	arch   emulator.Arch
	handle *C.uc_engine
}

func New(arch emulator.Arch) (emulator.Emulator, error) {
	var uc_arch C.uc_arch
	var uc_mode C.uc_mode
	switch arch {
	case emulator.ARCH_ARM:
		uc_arch, uc_mode = C.UC_ARCH_ARM, C.UC_MODE_ARM
	case emulator.ARCH_ARM64:
		uc_arch, uc_mode = C.UC_ARCH_ARM64, C.UC_MODE_ARM
	case emulator.ARCH_X86:
		uc_arch, uc_mode = C.UC_ARCH_X86, C.UC_MODE_32
	case emulator.ARCH_X86_64:
		uc_arch, uc_mode = C.UC_ARCH_X86, C.UC_MODE_64
	default:
		return nil, emulator.ErrArchUnsupported
	}
	var handle *C.uc_engine
	err := errCheck(C.uc_open(uc_arch, uc_mode, &handle))
	if err != nil {
		return nil, err
	}
	u := &unicorn{arch: arch, handle: handle}
	return u, nil
}

func (u *unicorn) Close() error {
	return errCheck(C.uc_close(u.handle))
}

func (u *unicorn) Arch() emulator.Arch {
	return u.arch
}

func (u *unicorn) ByteOrder() emulator.ByteOrder {
	return emulator.BO_LITTLE_ENDIAN
}

func (u *unicorn) PageSize() uint64 {
	return 0x1000
}

func (u *unicorn) MemMap(addr, size uint64, prot emulator.MemProt) error {
	return errCheck(C.uc_mem_map(u.handle, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot)))
}

func (u *unicorn) MemMapPtr(addr, size uint64, prot emulator.MemProt, ptr unsafe.Pointer) error {
	return errCheck(C.uc_mem_map_ptr(u.handle, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot), ptr))
}

func (u *unicorn) MemUnmap(addr, size uint64) error {
	return errCheck(C.uc_mem_unmap(u.handle, C.uint64_t(addr), C.size_t(size)))
}

func (u *unicorn) MemProtect(addr, size uint64, prot emulator.MemProt) error {
	return errCheck(C.uc_mem_protect(u.handle, C.uint64_t(addr), C.size_t(size), C.uint32_t(prot)))
}

func (u *unicorn) MemRegions() ([]emulator.MemRegion, error) {
	var regions *C.uc_mem_region
	var count C.uint32_t
	ucerr := C.uc_mem_regions(u.handle, &regions, &count)
	if ucerr != C.UC_ERR_OK {
		return nil, errCheck(ucerr)
	}
	ret := make([]emulator.MemRegion, count)
	for i, region := range unsafe.Slice(regions, count) {
		ret[i] = emulator.MemRegion{
			Addr: uint64(region.begin), Size: uint64(region.end - region.begin),
			Prot: emulator.MemProt(region.perms),
		}
	}
	C.uc_free(unsafe.Pointer(regions))
	return ret, nil
}

func (u *unicorn) MemRead(addr, size uint64) (data []byte, err error) {
	if size != 0 {
		data = make([]byte, size)
		err = u.MemReadPtr(addr, size, unsafe.Pointer(unsafe.SliceData(data)))
	}
	return
}

func (u *unicorn) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return u.MemWritePtr(addr, uint64(len(data)), unsafe.Pointer(unsafe.SliceData(data)))
}

func (u *unicorn) MemReadPtr(addr, size uint64, ptr unsafe.Pointer) error {
	return errCheck(C.mem_read(u.handle, C.uint64_t(addr), C.uintptr_t(uintptr(ptr)), C.size_t(size)))
}

func (u *unicorn) MemWritePtr(addr, size uint64, ptr unsafe.Pointer) error {
	return errCheck(C.mem_write(u.handle, C.uint64_t(addr), C.uintptr_t(uintptr(ptr)), C.size_t(size)))
}

func (u *unicorn) RegRead(reg emulator.Reg) (uint64, error) {
	var value uint64
	return value, u.RegReadPtr(reg, unsafe.Pointer(&value))
}

func (u *unicorn) RegWrite(reg emulator.Reg, value uint64) error {
	return u.RegWritePtr(reg, unsafe.Pointer(&value))
}

func (u *unicorn) RegReadPtr(reg emulator.Reg, ptr unsafe.Pointer) error {
	return errCheck(C.uc_reg_read(u.handle, C.int(reg), ptr))
}

func (u *unicorn) RegWritePtr(reg emulator.Reg, ptr unsafe.Pointer) error {
	return errCheck(C.uc_reg_write(u.handle, C.int(reg), ptr))
}

func (u *unicorn) RegReadBatch(regs ...emulator.Reg) ([]uint64, error) {
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
	return vals, errCheck(C.uc_reg_read_batch(u.handle, unsafe.SliceData(cregs), (*unsafe.Pointer)(unsafe.Pointer(unsafe.SliceData(cvals))), C.int(len(regs))))
}

func (u *unicorn) RegWriteBatch(regs []emulator.Reg, vals []uint64) error {
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
	return errCheck(C.uc_reg_write_batch(u.handle, unsafe.SliceData(cregs), (*unsafe.Pointer)(unsafe.Pointer(unsafe.SliceData(cvals))), C.int(len(regs))))
}

func (u *unicorn) Start(begin, until uint64) error {
	return errCheck(C.uc_emu_start(u.handle, C.uint64_t(begin), C.uint64_t(until), 0, 0))
}

func (u *unicorn) Stop() error {
	return errCheck(C.uc_emu_stop(u.handle))
}
