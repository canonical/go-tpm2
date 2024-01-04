// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package union

// Contents is a helper for union types. It holds any type, and should
// be embedded as a non-exported field of a structure that represents a union.
// It holds a pointer to the union value.
type Contents any

// NewContents returns a new Contents for the specified value. It holds
// a pointer to the supplied value.
func NewContents[T any](contents T) Contents {
	return Contents(&contents)
}

// ContentsElem returns the value of the union contents. This will panic
// if the contents has a value of the wrong type.
func ContentsElem[T any](contents Contents) T {
	return *(contents.(*T))
}

// ContentsPtr returns a pointer to the union contents. This will panic
// if the contents has a value of the wrong type.
func ContentsPtr[T any](contents Contents) *T {
	return contents.(*T)
}

// ContentsMarshal returns the value of the union contents. If the contents
// are nil, then the zero value will be returned. This will return nil if the
// contents contains a value of an incompatible type.
func ContentsMarshal[T any](contents Contents) any {
	if contents == nil {
		var zeroValue T
		return zeroValue
	}
	ptr, ok := contents.(*T)
	if !ok {
		return nil
	}
	return *ptr
}

// ContentsUnmarshal returns a pointer to the union contents, allocating
// a new value of the correct type if required.
func ContentsUnmarshal[T any](contents *Contents) any {
	ptr, ok := (*contents).(*T)
	if !ok {
		ptr = new(T)
		*contents = ptr
	}
	return ptr
}
