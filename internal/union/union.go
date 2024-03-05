// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package union

// Contents is a helper for union types. It holds any type, and should
// be embedded as a non-exported field of a structure that represents a union.
// It holds a pointer to the union value, and therefore copying this value
// doesn't copy the underlying data.
type Contents struct {
	data any
}

// NewContents returns a new Contents for the specified value. It holds
// a pointer to the supplied value.
func NewContents[T any](contents T) Contents {
	return Contents{data: &contents}
}

// ContentsElem returns the value of the union contents. This will panic
// if the contents has a value of the wrong type.
func ContentsElem[T any](contents Contents) T {
	return *(contents.data.(*T))
}

// ContentsPtr returns a pointer to the union contents. This will panic
// if the contents has a value of the wrong type.
func ContentsPtr[T any](contents Contents) *T {
	return contents.data.(*T)
}

// ContentsIs indicates whether the union contents contains the specified
// type.
func ContentsIs[T any](contents Contents) bool {
	_, ok := contents.data.(*T)
	return ok
}

// ContentsMarshal returns the value of the union contents. If the contents
// are nil, then the zero value will be returned. This will return the zero
// value if the contents contains a value of a different type.
func ContentsMarshal[T any](contents Contents) T {
	ptr, ok := contents.data.(*T)
	if !ok {
		var zeroValue T
		return zeroValue
	}

	return *ptr
}

// ContentsUnmarshal returns a pointer to the union contents, allocating
// a new value of the correct type if required.
func ContentsUnmarshal[T any](contents *Contents) *T {
	ptr, ok := contents.data.(*T)
	if !ok {
		ptr = new(T)
		contents.data = ptr
	}
	return ptr
}
