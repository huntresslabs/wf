package wf

import (
	"strings"
)

var _FilterEnumFlagsNames = [6]string{
	"BestTerminatingMatch",
	"Sorted",
	"BootTimeOnly",
	"IncludeBootTime",
	"IncludeDisabled",
	"Reserved1",
}

const _FilterEnumFlags_name = "FullyContainedOverlapping"

var _FilterEnumFlags_index = [...]uint8{0, 14, 25}

func (e FilterEnumFlags) String() string {
	flags := []string{}
	for i := 0; i < len(_FilterEnumFlagsNames); i++ {
		if ((e >> i) & 1) == 1 {
			flags = append(flags, _FilterEnumFlagsNames[i])
		}
	}
	return "FilterEnumFlags(" + strings.Join(flags, "|") + ")"
}
