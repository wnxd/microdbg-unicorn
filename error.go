package unicorn

// #include "unicorn/unicorn.h"
import "C"

type ucError C.uc_err

func (u ucError) Error() string {
	return C.GoString(C.uc_strerror(C.uc_err(u)))
}

func errCheck(err C.uc_err) error {
	if err != C.UC_ERR_OK {
		return ucError(err)
	}
	return nil
}
