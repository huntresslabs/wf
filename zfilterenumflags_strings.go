// Code generated by "stringer -output=zfilterenumflags_strings.go -type=FilterEnumFlags -trimprefix=FilterEnumFlags"; DO NOT EDIT.

package wf

import "strconv"

func _() {
	// An "invalid array index" compiler error signifies that the constant values have changed.
	// Re-run the stringer command to generate them again.
	var x [1]struct{}
	_ = x[FilterEnumFlagsBestTerminatingMatch-1]
	_ = x[FilterEnumFlagsSorted-2]
	_ = x[FilterEnumFlagsBootTimeOnly-3]
	_ = x[FilterEnumFlagsIncludeBootTime-4]
	_ = x[FilterEnumFlagsIncludeDisabled-5]
}

const _FilterEnumFlags_name = "BestTerminatingMatchSortedBootTimeOnlyIncludeBootTimeIncludeDisabled"

var _FilterEnumFlags_index = [...]uint8{0, 20, 26, 38, 53, 68}

func (i FilterEnumFlags) String() string {
	i -= 1
	if i >= FilterEnumFlags(len(_FilterEnumFlags_index)-1) {
		return "FilterEnumFlags(" + strconv.FormatInt(int64(i+1), 10) + ")"
	}
	return _FilterEnumFlags_name[_FilterEnumFlags_index[i]:_FilterEnumFlags_index[i+1]]
}