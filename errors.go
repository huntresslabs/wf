package wf

import (
	"syscall"
)

const (
	FilterNotFound   syscall.Errno = 0x80320003
	LayerNotFound                  = 0x80320004
	ProviderNotFound               = 0x80320005
	SublayerNotFound               = 0x80320007
	NotFound                       = 0x80320008
)
