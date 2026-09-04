// Command libnordyg is the C surface of the Nordyg core, built with
// -buildmode=c-archive. It exposes exactly three functions; everything else is
// the JSON contract handled by internal/bridge.
//
//	char* NordygQuery(const char* request_json);   // caller frees with NordygFree
//	void  NordygCancel(const char* request_id);
//	void  NordygFree(char* p);
package main

/*
#include <stdlib.h>

// cgo maps *C.char to plain char*. The typedef lets the exported signatures
// take const char*, so Swift sees UnsafePointer<CChar> and can pass the
// pointer from withCString directly.
typedef const char nordyg_cstr;
*/
import "C"

import (
	"unsafe"

	"github.com/n0rdy/nordyg/core/internal/ops"
)

var dispatcher = ops.New()

func goString(p *C.nordyg_cstr) string {
	return C.GoString((*C.char)(unsafe.Pointer(p)))
}

// NordygQuery runs one request and returns the JSON response as a C string the
// caller must release with NordygFree. It never returns NULL and never panics.
//
//export NordygQuery
func NordygQuery(request *C.nordyg_cstr) *C.char {
	if request == nil {
		return C.CString(`{"id":"","ok":false,"error":{"code":"bad_request","message":"null request"}}`)
	}
	return C.CString(string(dispatcher.Dispatch([]byte(goString(request)))))
}

// NordygCancel aborts the in-flight request with the given id. Unknown ids are
// ignored.
//
//export NordygCancel
func NordygCancel(id *C.nordyg_cstr) {
	if id == nil {
		return
	}
	dispatcher.Cancel(goString(id))
}

// NordygFree releases a string returned by NordygQuery.
//
//export NordygFree
func NordygFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}
