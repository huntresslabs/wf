package wf

import (
	"strings"
)

var _FilterEnumTypeNames = [6]string{
	"BestTerminatingMatch",
	"Sorted",
	"BootTimeOnly",
	"IncludeBootTime",
	"IncludeDisabled",
	"Reserved1",
}

const _FilterEnumType_name = "FullyContainedOverlapping"

var _FilterEnumType_index = [...]uint8{0, 14, 25}

func (e FilterEnumType) String() string {
	flags := []string{}
	for i := 0; i < len(_FilterEnumTypeNames); i++ {
		if ((e >> i) & 1) == 1 {
			flags = append(flags, _FilterEnumTypeNames[i])
		}
	}
	return "FilterEnumFlags(" + strings.Join(flags, "|") + ")"
}
