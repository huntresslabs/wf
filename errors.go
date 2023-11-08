package wf

import (
	"syscall"
)

// Detailed error code information available here:
// https://learn.microsoft.com/en-us/windows/win32/fwp/wfp-error-codes
const (
	FilterNotFound          syscall.Errno = 0x80320003
	LayerNotFound                         = 0x80320004
	ProviderNotFound                      = 0x80320005
	SublayerNotFound                      = 0x80320007
	NotFound                              = 0x80320008
	NoTransactionInProgress               = 0x8032000D
	TransactionInProgress                 = 0x8032000E
	TransactionAborted                    = 0x8032000F
	Timeout                               = 0x80320012
	NilPointer                            = 0x8032001C
)
