// Copyright (C) 2020 Huntress Labs, Inc.
//
// This file is part of Huntress. Unauthorized copying of this file, via any medium is
// strictly prohibited without the express written consent of Huntress Labs, Inc.

package wf

import (
	"testing"
	"unsafe"
)

func TestMemoryAllocation(t *testing.T) {
	var a arena
	defer a.Dispose()

	// This should have an alignment of 8-bytes
	// ref: https://go.dev/ref/spec#Size_and_alignment_guarantees
	var ip *int64

	// allocate from 8 to 15 bytes.  Each allocation should end up on the boundary size
	for i := 0; i < byteBoundary; i++ {
		p := a.Alloc(unsafe.Sizeof(ip) + uintptr(i))

		if uintptr(p)%byteBoundary != 0 {
			t.Fatalf("allocation not on %v-byte boundary", byteBoundary)
		}

		ip = (*int64)(p)

		// verify we can write to the pointer
		*ip = 0
	}
}

func TestMemoryAllocationSpanSlabsWithRounding(t *testing.T) {
	var a arena
	defer a.Dispose()

	// allocate almost a full slab size
	// This will likely round to the end of the slab
	size := slabSize - (byteBoundary / 2)
	p := a.Alloc(uintptr(size))
	ip := (*int64)(p)
	*ip = 0

	// This should force us over the current slab of memory.
	p = a.Alloc(byteBoundary)
	ip = (*int64)(p)
	*ip = 0
}

func TestMemoryAllocationSpanSlabsWithRoundingSmaller(t *testing.T) {
	var a arena
	defer a.Dispose()

	// allocate almost a full slab size
	// This will likely round to the end of the slab
	size := slabSize - (byteBoundary / 2)
	p := a.Alloc(uintptr(size))
	ip := (*int64)(p)
	*ip = 0

	// allocate a small amount
	p = a.Alloc(uintptr(1))
	if p == nil {
		t.Fatal("invalid address returned")
	}

	// This should force us over the current slab of memory.
	p = a.Alloc(byteBoundary)
	ip = (*int64)(p)
	*ip = 0
}

func TestMemoryAllocationSpanSlabsWithRoundingSmallerWithSlab(t *testing.T) {
	var a arena
	defer a.Dispose()

	// allocate almost a full slab size
	// This will likely round to the end of the slab
	size := slabSize - (byteBoundary / 2)
	p := a.Alloc(uintptr(size))
	ip := (*int64)(p)
	*ip = 0

	// allocate a small amount
	p = a.Alloc(uintptr(1))
	if p == nil {
		t.Fatal("invalid address returned")
	}

	// This should force us over the current slab of memory.
	p = a.Alloc(byteBoundary)
	ip = (*int64)(p)
	*ip = 0

	// Try one more allocation with a slab size
	p = a.Alloc(slabSize)
	ip = (*int64)(p)
	*ip = 0

	// allocate one more small amount
	p = a.Alloc(uintptr(1))
	if p == nil {
		t.Fatal("invalid address returned")
	}
}

func TestMemoryAllocationSpanSlabWithoutRounding(t *testing.T) {
	var a arena
	defer a.Dispose()

	// allocate almost a full slab size, but back off an amount that is
	// bigger than our boundary size so that we know that
	// we would not have rounded to the end of the slab
	size := slabSize - (byteBoundary * 2)
	p := a.Alloc(uintptr(size))
	ip := (*int64)(p)
	*ip = 0

	// Allocate more than we backed off of so we know that our allocation
	// will go over amount we have left in our slab
	p = a.Alloc(uintptr(byteBoundary * 3))
	ip = (*int64)(p)
	*ip = 0
}
