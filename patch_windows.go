//go:build windows

package unicorn

/*
#include <windows.h>

static LONG patch_handler(PEXCEPTION_POINTERS ex) {
	PEXCEPTION_RECORD record = ex->ExceptionRecord;
	if (record->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
		return EXCEPTION_CONTINUE_SEARCH;
	LPVOID addr = (LPVOID)(record->ExceptionInformation[1]);
	MEMORY_BASIC_INFORMATION buf;
	if (VirtualQuery(addr, &buf, sizeof(buf)) == 0)
		return EXCEPTION_CONTINUE_SEARCH;
	return buf.State&MEM_COMMIT ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

void patch() {
	AddVectoredContinueHandler(1, patch_handler);
}
*/
import "C"

func init() {
	C.patch()
}
