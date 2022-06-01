// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"

	"golang.org/x/xerrors"
)

var (
	customMarshallerType   reflect.Type = reflect.TypeOf((*customMarshallerIface)(nil)).Elem()
	customUnmarshallerType reflect.Type = reflect.TypeOf((*customUnmarshallerIface)(nil)).Elem()
	unionType              reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
	nilValueType           reflect.Type = reflect.TypeOf(NilUnionValue)
	rawBytesType           reflect.Type = reflect.TypeOf(RawBytes(nil))
)

// InvalidSelectorError may be returned as a wrapped error from UnmarshalFromBytes or
// UnmarshalFromReader when a union type indicates that a selector value is invalid.
type InvalidSelectorError struct {
	Selector reflect.Value
}

func (e *InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

type customMarshallerIface interface {
	Marshal(w io.Writer) error
}

type customUnmarshallerIface interface {
	Unmarshal(r Reader) error
}

// CustomMarshaller is implemented by types that require custom marshalling
// behaviour because they are non-standard and not directly supported by this
// package.marshalling code.
//
// If the implementation makes a recursive call in to this package, it should
// return errors from any recursive call without wrapping. This allows the full
// context of the error to be surfaced from the originating call.
type CustomMarshaller interface {
	// Marshal should serialize the value to the supplied writer.
	// The implementation of this must take a value receiver.
	Marshal(w io.Writer) error

	// Unmarshal should unserialize the value from the supplied reader.
	// The implementation of this should take a pointer receiver.
	Unmarshal(r Reader) error
}

var _ CustomMarshaller = struct {
	customMarshallerIface
	customUnmarshallerIface
}{}

type empty struct{}

// NilUnionValue is a special value, the type of which should be returned from implementations
// of Union.Select to indicate that a union contains no data for a particular selector value.
var NilUnionValue empty

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a
// size field. The slice must be pre-allocated to the correct length by the caller during
// unmarshalling.
type RawBytes []byte

type wrappedValue struct {
	value interface{}
	opts  *options
}

// Raw converts the supplied value, which should be a slice, to a raw slice.
// A raw slice is one that is marshalled without a corresponding size or
// length field.
//
// To unmarshal a raw slice, the supplied value must be a pointer to the
// preallocated destination slice.
func Raw(val interface{}) *wrappedValue {
	return &wrappedValue{value: val, opts: &options{raw: true}}
}

// Sized converts the supplied value to a sized value.
//
// To marshal a sized value, the supplied value must be a pointer to the actual
// value.
//
// To unmarshal a sized value, the supplied value must be a pointer to the
// destination pointer that will point to the unmarshalled value.
func Sized(val interface{}) *wrappedValue {
	return &wrappedValue{value: val, opts: &options{sized: true}}
}

// Union is implemented by structure types that correspond to TPMU prefixed TPM types.
// A struct that contains a union member automatically becomes a tagged union. The
// selector field is the first member of the tagged union, unless overridden with the
// `tpm2:"selector:<field_name>"` tag.
//
// Go doesn't have support for unions - TPMU types must be implemented with
// a struct that contains a field for each possible value.
//
// Implementations of this must be addressable.
type Union interface {
	// Select is called by this package to map the supplied selector value
	// to a field. The returned value must be a pointer to the selected field.
	// For this to work correctly, implementations must take a pointer receiver
	// and therefore.
	//
	// If the supplied selector value maps to no data, return NilUnionValue.
	//
	// If nil is returned, this is interpreted as an error.
	Select(selector reflect.Value) interface{}
}

type containerNode struct {
	value reflect.Value
	index int
	entry [1]uintptr
}

type containerStack []containerNode

func (s containerStack) push(node containerNode) containerStack {
	return append(s, node)
}

func (s containerStack) pop() containerStack {
	return s[:len(s)-1]
}

func (s containerStack) top() containerNode {
	return s[len(s)-1]
}

func (s containerStack) String() string {
	str := new(bytes.Buffer)
	str.WriteString("=== BEGIN STACK ===\n")
	for i := len(s) - 1; i >= 0; i-- {
		switch {
		case s[i].entry != [1]uintptr{0}:
			frames := runtime.CallersFrames(s[i].entry[:])
			frame, _ := frames.Next()
			fmt.Fprintf(str, "... %s custom type, call from %s:%d argument %d\n", s[i].value.Type(), frame.File, frame.Line, s[i].index)
		case s[i].value.Kind() == reflect.Struct:
			fmt.Fprintf(str, "... %s field %s\n", s[i].value.Type(), s[i].value.Type().Field(s[i].index).Name)
		case s[i].value.Kind() == reflect.Slice:
			fmt.Fprintf(str, "... %s index %d\n", s[i].value.Type(), s[i].index)
		default:
			panic("unsupported kind")
		}
	}
	str.WriteString("=== END STACK ===\n")

	return str.String()
}

// Error is returned from any function in this package to provide context
// of where an error occurred.
type Error struct {
	// Index indicates the argument on which this error occurred.
	Index int

	Op string

	total    int
	entry    [1]uintptr
	stack    containerStack
	leafType reflect.Type
	err      error
}

func (e *Error) Error() string {
	s := new(bytes.Buffer)
	fmt.Fprintf(s, "cannot %s argument ", e.Op)
	if e.total > 1 {
		fmt.Fprintf(s, "%d ", e.Index)
	}
	fmt.Fprintf(s, "whilst processing element of type %s: %v", e.leafType, e.err)
	if len(e.stack) != 0 {
		fmt.Fprintf(s, "\n\n%s", e.stack)
	}
	return s.String()
}

func (e *Error) Unwrap() error {
	return e.err
}

// Type returns the type of the value on which this error occurred.
func (e *Error) Type() reflect.Type {
	return e.leafType
}

// Depth returns the depth of the value on which this error occurred.
func (e *Error) Depth() int {
	return len(e.stack)
}

// Container returns the type of the container at the specified depth.
//
// If the returned type is a structure, the returned index corresponds
// to the index of the field in that structure.
//
// If the returned type is a slice, the returned index corresponds to
// the index in that slice.
//
// If the returned type implements the CustomMarshaller and
// CustomUnmarshaller interfaces, the returned index corresponds to
// the argument index in the recursive call in to one of the marshalling
// or unmarshalling APIs. The returned frame indicates where this
// recursive call originated from.
func (e *Error) Container(depth int) (containerType reflect.Type, index int, entry runtime.Frame) {
	var frame runtime.Frame
	if e.stack[depth].entry != [1]uintptr{0} {
		frames := runtime.CallersFrames(e.stack[depth].entry[:])
		frame, _ = frames.Next()
	}

	return e.stack[depth].value.Type(), e.stack[depth].index, frame
}

func newError(value reflect.Value, c *context, err error) error {
	if err == io.EOF {
		// All io.EOF is unexpected
		err = io.ErrUnexpectedEOF
	}
	muErr, isMuErr := err.(*Error)

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)

	var leafType reflect.Type
	if isMuErr {
		// This is an error returned from a custom type.
		// Preserve the original error
		err = muErr.err

		// Copy the leaf type to the new error
		leafType = muErr.leafType

		// Append the original error stack to the new error.
		stack = stack.push(containerNode{value: value, index: muErr.Index, entry: muErr.entry})
		stack = append(stack, muErr.stack...)
	} else {
		leafType = value.Type()
	}

	return &Error{
		Index:    c.index,
		Op:       c.mode,
		total:    c.total,
		entry:    c.caller,
		stack:    stack,
		leafType: leafType,
		err:      err}
}

type options struct {
	selector string
	sized    bool
	raw      bool
}

func parseStructFieldMuOptions(f reflect.StructField) (out *options) {
	out = new(options)

	s := f.Tag.Get("tpm2")
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "selector:"):
			out.selector = part[9:]
		case part == "sized":
			out.sized = true
		case part == "raw":
			out.raw = true
		}
	}

	return out
}

type context struct {
	caller [1]uintptr // address of the function calling into the public API
	mode   string     // marshal or unmarshal
	index  int        // current argument index
	total  int        // total number of arguments
	stack  containerStack
	sized  bool
}

func (c *context) enterStructField(s reflect.Value, i int) (exit func()) {
	c.stack = c.stack.push(containerNode{value: s, index: i})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) enterListElem(l reflect.Value, i int) (exit func()) {
	c.stack = c.stack.push(containerNode{value: l, index: i})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) enterUnionElem(u reflect.Value, opts *options) (elem reflect.Value, exit func(), err error) {
	if len(c.stack) == 0 || c.stack.top().value.Kind() != reflect.Struct {
		panic(fmt.Sprintf("union type %s is not inside a struct\n%s", u.Type(), c.stack))
	}

	var selectorVal reflect.Value
	if opts == nil || opts.selector == "" {
		selectorVal = c.stack.top().value.Field(0)
	} else {
		selectorVal = c.stack.top().value.FieldByName(opts.selector)
		if !selectorVal.IsValid() {
			panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field\n%s",
				opts.selector, u.Type(), c.stack))
		}
	}

	if !u.CanAddr() {
		panic(fmt.Sprintf("union type %s needs to be referenced via a pointer field\n%s", u.Type(), c.stack))
	}

	p := u.Addr().Interface().(Union).Select(selectorVal)
	switch {
	case p == nil:
		return reflect.Value{}, nil, &InvalidSelectorError{selectorVal}
	case p == NilUnionValue:
		return reflect.Value{}, nil, nil
	}
	pv := reflect.ValueOf(p)

	index := -1
	for i := 0; i < u.NumField(); i++ {
		if u.Field(i).Addr().Interface() == pv.Interface() {
			index = i
			break
		}
	}
	if index == -1 {
		panic(fmt.Sprintf("Union.Select implementation for type %s returned a non-member pointer\n%s",
			u.Type(), c.stack))
	}

	return pv.Elem(), c.enterStructField(u, index), nil
}

func (c *context) enterSizedType() (exit func()) {
	orig := c.sized
	c.sized = true
	return func() {
		c.sized = orig
	}
}

// TPMKind indicates the TPM type class associated with a Go type
type TPMKind int

const (
	// TPMKindUnsupported indicates that a go type has no corresponding
	// TPM type class.
	TPMKindUnsupported TPMKind = iota

	// TPMKindPrimitive indicates that a go type corresponds to one
	// of the primitive TPM types (UINT8, BYTE, INT8, BOOL, UINT16,
	// INT16, UINT32, INT32, UINT64, INT64, TPM_ALG_ID, any TPMA_
	// prefixed type).
	TPMKindPrimitive

	// TPMKindSized indicates that a go type corresponds to a
	// TPM2B prefixed TPM type.
	TPMKindSized

	// TPMKindList indicates that a go type corresponds to a
	// TPML prefixed TPM type.
	TPMKindList

	// TPMKindStruct indicates that a go type corresponds to a
	// TPMS prefixed TPM type.
	TPMKindStruct

	// TPMKindTaggedUnion indicates that a go type corresponds
	// to a TPMT prefixed TPM type.
	TPMKindTaggedUnion

	// TPMKindUnion indicates that a go type corresponds to a
	// TPMU prefixed TPM type.
	TPMKindUnion

	// TPMKindCustom correponds to a go type that defines its own
	// marshalling behaviour.
	TPMKindCustom

	// TPMKindRaw corresponds to a go slice that is marshalled
	// without a size field. It behaves like a sequence of
	// individual values.
	TPMKindRaw
)

func tpmKind(t reflect.Type, c *context, o *options) (TPMKind, error) {
	if o == nil {
		var def options
		o = &def
	}

	if t.Kind() != reflect.Ptr {
		switch {
		case t.Implements(customMarshallerType) && reflect.PtrTo(t).Implements(customUnmarshallerType):
			if o.raw || o.sized || o.selector != "" {
				return TPMKindUnsupported, errors.New(`"raw", "sized" and "selector" options are invalid with custom types`)
			}
			return TPMKindCustom, nil
		case reflect.PtrTo(t).Implements(unionType):
			if o.raw || o.sized {
				return TPMKindUnsupported, errors.New(`"raw" and "sized" options are invalid with union types`)
			}
			return TPMKindUnion, nil
		}
	}

	sized := false
	if c != nil {
		sized = c.sized
	}

	switch t.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if o.sized || o.raw || o.selector != "" {
			return TPMKindUnsupported, errors.New(`"sized", "raw" and "selector" options are invalid with primitive types`)
		}
		return TPMKindPrimitive, nil
	case reflect.Ptr:
		if k, _ := tpmKind(t.Elem(), nil, nil); k != TPMKindStruct && k != TPMKindTaggedUnion {
			return TPMKindUnsupported, nil
		}

		switch {
		case o.sized:
			return TPMKindSized, nil
		case o.raw || o.selector != "":
			return TPMKindUnsupported, errors.New(`"raw" and "selector" options are invalid with struct types`)
		default:
			return TPMKindUnsupported, nil
		}
	case reflect.Slice:
		switch {
		case t == rawBytesType:
			return TPMKindRaw, nil
		case o.sized || o.selector != "":
			return TPMKindUnsupported, errors.New(`"sized" and "selector" options are invalid with slice types`)
		case o.raw:
			return TPMKindRaw, nil
		case t.Elem().Kind() == reflect.Uint8:
			if sized {
				return TPMKindRaw, nil
			}
			return TPMKindSized, nil
		default:
			return TPMKindList, nil
		}
	case reflect.Struct:
		k := TPMKindStruct

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				// structs with unexported fields are unsupported
				return TPMKindUnsupported, errors.New("struct type with unexported fields")
			}
			if f.Type.Kind() != reflect.Ptr {
				continue
			}
			if fk, _ := tpmKind(f.Type.Elem(), nil, nil); fk == TPMKindUnion {
				k = TPMKindTaggedUnion
			}
		}

		if o.sized {
			return TPMKindUnsupported, errors.New(`"sized" option requires a pointer field`)
		}
		if o.raw || o.selector != "" {
			return TPMKindUnsupported, errors.New(`"raw" and "selector" options are invalid with struct types`)
		}

		return k, nil
	default:
		return TPMKindUnsupported, fmt.Errorf("unsupported kind: %v", t.Kind())
	}

}

func tpmKindCheckStructFieldRecursive(t, c reflect.Type, f reflect.StructField) TPMKind {
	opts := parseStructFieldMuOptions(f)
	k := tpmKindCheckRecursive(t, c, opts)
	if k == TPMKindUnion {
		if opts.selector != "" {
			if _, found := c.FieldByName(opts.selector); !found {
				return TPMKindUnsupported
			}
		}
		if f.Type.Kind() != reflect.Ptr {
			return TPMKindUnsupported
		}
	}
	return k
}

func tpmKindCheckRecursive(t, c reflect.Type, opts *options) (ret TPMKind) {
	for {
		k, err := tpmKind(t, nil, opts)
		switch {
		case err != nil:
			return TPMKindUnsupported
		case k == TPMKindUnsupported:
			t = t.Elem()
		case k == TPMKindSized && t.Kind() == reflect.Ptr:
			// sized structure case
			if e := tpmKindCheckRecursive(t, c, nil); e == TPMKindUnsupported {
				return TPMKindUnsupported
			}
			return k
		case k == TPMKindList:
			if e := tpmKindCheckRecursive(t.Elem(), t, nil); e == TPMKindUnsupported {
				return TPMKindUnsupported
			}
			return k
		case k == TPMKindStruct || k == TPMKindTaggedUnion:
			for i := 0; i < t.NumField(); i++ {
				if e := tpmKindCheckStructFieldRecursive(t.Field(i).Type, t, t.Field(i)); e == TPMKindUnsupported {
					return TPMKindUnsupported
				}
			}
			return k
		case k == TPMKindUnion:
			if c != nil {
				if parent, _ := tpmKind(c, nil, nil); parent != TPMKindTaggedUnion {
					return TPMKindUnsupported
				}
			}

			for i := 0; i < t.NumField(); i++ {
				if e := tpmKindCheckRecursive(t.Field(i).Type, t, nil); e == TPMKindUnsupported {
					return TPMKindUnsupported
				}
			}

			return k
		case k == TPMKindRaw && t.Elem().Kind() != reflect.Uint8:
			// raw list case
			if e := tpmKindCheckRecursive(t.Elem(), t, nil); e == TPMKindUnsupported {
				return TPMKindUnsupported
			}
			return k
		default:
			return k
		}
	}
}

// DetermineTPMKind returns the TPMKind associated with the supplied go value. It will
// automatically dereference pointer types.
//
// For slices and structures, this will recursively check that all elements / fields
// map to a supported TPMKind. If TPMKindUnsupported is returned, the value will
// generate a panic either during marshalling or unmarshalling.
func DetermineTPMKind(i interface{}) TPMKind {
	switch v := i.(type) {
	case *wrappedValue:
		return tpmKindCheckRecursive(reflect.TypeOf(v.value), nil, v.opts)
	default:
		return tpmKindCheckRecursive(reflect.TypeOf(i), nil, nil)
	}
}

type marshaller struct {
	*context
	w      io.Writer
	nbytes int
}

func (m *marshaller) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.nbytes += n
	return
}

func (m *marshaller) marshalSized(v reflect.Value) error {
	exit := m.enterSizedType()
	defer exit()

	if v.IsNil() {
		if err := binary.Write(m, binary.BigEndian, uint16(0)); err != nil {
			return newError(v, m.context, err)
		}
		return nil
	}

	tmpBuf := new(bytes.Buffer)
	sm := &marshaller{context: m.context, w: tmpBuf}
	if err := sm.marshalValue(v, nil); err != nil {
		return err
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return newError(v, m.context, fmt.Errorf("sized value size of %d is larger than 2^16-1", tmpBuf.Len()))
	}
	if err := binary.Write(m, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return newError(v, m.context, err)
	}
	if _, err := tmpBuf.WriteTo(m); err != nil {
		return newError(v, m.context, err)
	}
	return nil
}

func (m *marshaller) marshalRawList(v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		exit := m.enterListElem(v, i)
		if err := m.marshalValue(v.Index(i), nil); err != nil {
			exit()
			return err
		}
		exit()
	}
	return nil
}

func (m *marshaller) marshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		if _, err := m.Write(v.Bytes()); err != nil {
			return newError(v, m.context, err)
		}
		return nil
	default:
		return m.marshalRawList(v)
	}
}

func (m *marshaller) marshalPtr(v reflect.Value, opts *options) error {
	p := v
	if v.IsNil() {
		p = reflect.New(v.Type().Elem())
	}
	return m.marshalValue(p.Elem(), opts)
}

func (m *marshaller) marshalPrimitive(v reflect.Value) error {
	if err := binary.Write(m, binary.BigEndian, v.Interface()); err != nil {
		return newError(v, m.context, err)
	}
	return nil
}

func (m *marshaller) marshalList(v reflect.Value) error {
	// int is either 32-bits or 64-bits. We can't compare slice.Len() to math.MaxUint32 when int is 32-bits and it isn't
	// necessary anyway. For the case where int is 64-bits, truncate to uint32 then zero extend it again to int to make
	// sure the original number was preserved.
	if int(uint32(v.Len())) != v.Len() {
		return newError(v, m.context, fmt.Errorf("slice length of %d is larger than 2^32-1", v.Len()))
	}

	// Marshal length field
	if err := binary.Write(m, binary.BigEndian, uint32(v.Len())); err != nil {
		return newError(v, m.context, err)
	}

	return m.marshalRawList(v)
}

func (m *marshaller) marshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		exit := m.enterStructField(v, i)
		if err := m.marshalValue(v.Field(i), parseStructFieldMuOptions(v.Type().Field(i))); err != nil {
			exit()
			return err
		}
		exit()
	}

	return nil
}

func (m *marshaller) marshalUnion(v reflect.Value, opts *options) error {
	// Ignore during marshalling - let the TPM unmarshalling catch it
	elem, exit, _ := m.enterUnionElem(v, opts)
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return m.marshalValue(elem, nil)
}

func (m *marshaller) marshalCustom(v reflect.Value) error {
	if err := v.Interface().(customMarshallerIface).Marshal(m); err != nil {
		return newError(v, m.context, err)
	}
	return nil
}

func (m *marshaller) marshalValue(v reflect.Value, opts *options) error {
	kind, err := tpmKind(v.Type(), m.context, opts)

	switch {
	case err != nil:
		panic(fmt.Sprintf("cannot marshal unsupported type %s (%v)\n%s", v.Type(), err, m.stack))
	case kind == TPMKindUnsupported:
		return m.marshalPtr(v, opts)
	}

	m.sized = false

	switch kind {
	case TPMKindPrimitive:
		return m.marshalPrimitive(v)
	case TPMKindSized:
		return m.marshalSized(v)
	case TPMKindList:
		return m.marshalList(v)
	case TPMKindStruct, TPMKindTaggedUnion:
		return m.marshalStruct(v)
	case TPMKindUnion:
		return m.marshalUnion(v, opts)
	case TPMKindCustom:
		return m.marshalCustom(v)
	case TPMKindRaw:
		return m.marshalRaw(v)
	}

	panic("unhandled kind")
}

func (m *marshaller) marshal(vals ...interface{}) (int, error) {
	for i, v := range vals {
		m.index = i

		var opts *options
		switch w := v.(type) {
		case *wrappedValue:
			v = w.value
			opts = w.opts
		default:
		}

		if err := m.marshalValue(reflect.ValueOf(v), opts); err != nil {
			return m.nbytes, err
		}
	}
	return m.nbytes, nil
}

// Reader is an interface that groups the io.Reader interface with an additional method to
// obtain the remaining number of bytes that can be read for implementations that support this.
type Reader interface {
	io.Reader
	Len() int
}

type unmarshaller struct {
	*context
	r      io.Reader
	sz     int64
	nbytes int
}

func (u *unmarshaller) Read(p []byte) (n int, err error) {
	n, err = u.r.Read(p)
	u.nbytes += n
	return
}

func (u *unmarshaller) Len() int {
	return int(u.sz - int64(u.nbytes))
}

func startingSizeOfReader(r io.Reader) (int64, error) {
	switch rImpl := r.(type) {
	case *os.File:
		fi, err := rImpl.Stat()
		if err != nil {
			return 0, err
		}
		if fi.Mode().IsRegular() {
			start, err := rImpl.Seek(0, io.SeekCurrent)
			if err != nil {
				return 0, err
			}
			return fi.Size() - start, nil
		}
	case *bytes.Reader:
		return int64(rImpl.Len()), nil
	case *bytes.Buffer:
		return int64(rImpl.Len()), nil
	case *io.SectionReader:
		start, _ := rImpl.Seek(0, io.SeekCurrent)
		return rImpl.Size() - start, nil
	case *io.LimitedReader:
		sz, err := startingSizeOfReader(rImpl.R)
		if err != nil {
			return 0, err
		}
		if rImpl.N < sz {
			sz = rImpl.N
		}
		return sz, nil
	}
	return 1<<63 - 1, nil
}

func makeUnmarshaller(ctx *context, r io.Reader) (*unmarshaller, error) {
	sz, err := startingSizeOfReader(r)
	if err != nil {
		return nil, err
	}
	return &unmarshaller{context: ctx, r: r, sz: sz}, nil
}

func (u *unmarshaller) unmarshalSized(v reflect.Value) error {
	exit := u.enterSizedType()
	defer exit()

	var size uint16
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return newError(v, u.context, err)
	}

	// v is either:
	// - a pointer kind, in which case it is a pointer to a struct. This
	//   is the sized structure case.
	// - a slice kind, in which case the slice is always a byte slice. This
	//   is the sized buffer case.
	switch {
	case size == 0 && v.Kind() == reflect.Ptr:
		// zero sized structure. Clear the pointer if it was pre-set and
		// then return early.
		v.Set(reflect.Zero(v.Type()))
		return nil
	case int(size) > u.Len():
		return newError(v, u.context, fmt.Errorf("sized value has a size of %d bytes which is larger than the %d remaining bytes", size, u.Len()))
	case v.Kind() == reflect.Slice && (v.IsNil() || v.Cap() < int(size)):
		// sized buffer with no pre-allocated buffer or a pre-allocated
		// buffer that isn't large enough. Allocate a new one.
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	case v.Kind() == reflect.Slice:
		// sized buffer with pre-allocated buffer that is large enough.
		v.SetLen(int(size))
	}

	su, err := makeUnmarshaller(u.context, io.LimitReader(u, int64(size)))
	if err != nil {
		return newError(v, u.context, xerrors.Errorf("cannot create new reader for sized payload: %w", err))
	}
	return su.unmarshalValue(v, nil)
}

func (u *unmarshaller) unmarshalRawList(v reflect.Value, n int) (reflect.Value, error) {
	for i := 0; i < n; i++ {
		v = reflect.Append(v, reflect.Zero(v.Type().Elem()))
		exit := u.enterListElem(v, i)
		if err := u.unmarshalValue(v.Index(i), nil); err != nil {
			exit()
			return reflect.Value{}, err
		}
		exit()
	}
	return v, nil
}

func (u *unmarshaller) unmarshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		if _, err := io.ReadFull(u, v.Bytes()); err != nil {
			return newError(v, u.context, err)
		}
		return nil
	default:
		_, err := u.unmarshalRawList(v.Slice(0, 0), v.Len())
		return err
	}
}

func (u *unmarshaller) unmarshalPtr(v reflect.Value, opts *options) error {
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	return u.unmarshalValue(v.Elem(), opts)
}

func (u *unmarshaller) unmarshalPrimitive(v reflect.Value) error {
	if err := binary.Read(u, binary.BigEndian, v.Addr().Interface()); err != nil {
		return newError(v, u.context, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalList(v reflect.Value) error {
	// Unmarshal the length
	var length uint32
	if err := binary.Read(u, binary.BigEndian, &length); err != nil {
		return newError(v, u.context, err)
	}

	if v.IsNil() || v.Cap() < int(length) {
		v.Set(reflect.MakeSlice(v.Type(), 0, int(length)))
	}

	s, err := u.unmarshalRawList(v.Slice(0, 0), int(length))
	if err != nil {
		return err
	}
	v.Set(s)
	return nil
}

func (u *unmarshaller) unmarshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		exit := u.enterStructField(v, i)
		if err := u.unmarshalValue(v.Field(i), parseStructFieldMuOptions(v.Type().Field(i))); err != nil {
			exit()
			return err
		}
		exit()
	}
	return nil
}

func (u *unmarshaller) unmarshalUnion(v reflect.Value, opts *options) error {
	elem, exit, err := u.enterUnionElem(v, opts)
	if err != nil {
		return newError(v, u.context, err)
	}
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return u.unmarshalValue(elem, nil)
}

func (u *unmarshaller) unmarshalCustom(v reflect.Value) error {
	if !v.CanAddr() {
		panic(fmt.Sprintf("custom type %s needs to be referenced via a pointer field\n%s", v.Type(), u.stack))
	}
	if err := v.Addr().Interface().(customUnmarshallerIface).Unmarshal(u); err != nil {
		return newError(v, u.context, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalValue(v reflect.Value, opts *options) error {
	kind, err := tpmKind(v.Type(), u.context, opts)

	switch {
	case err != nil:
		panic(fmt.Sprintf("cannot unmarshal unsupported type %s (%v)\n%s", v.Type(), err, u.stack))
	case kind == TPMKindUnsupported:
		return u.unmarshalPtr(v, opts)
	}

	u.sized = false

	switch kind {
	case TPMKindPrimitive:
		return u.unmarshalPrimitive(v)
	case TPMKindSized:
		return u.unmarshalSized(v)
	case TPMKindList:
		return u.unmarshalList(v)
	case TPMKindStruct, TPMKindTaggedUnion:
		return u.unmarshalStruct(v)
	case TPMKindUnion:
		return u.unmarshalUnion(v, opts)
	case TPMKindCustom:
		return u.unmarshalCustom(v)
	case TPMKindRaw:
		return u.unmarshalRaw(v)
	}

	panic("unhandled kind")
}

func (u *unmarshaller) unmarshal(vals ...interface{}) (int, error) {
	for i, v := range vals {
		u.index = i

		var opts *options
		switch w := v.(type) {
		case *wrappedValue:
			v = w.value
			opts = w.opts
		default:
		}

		val := reflect.ValueOf(v)
		if val.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(v)))
		}

		if val.IsNil() {
			panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", val.Type()))
		}

		if err := u.unmarshalValue(val.Elem(), opts); err != nil {
			return u.nbytes, err
		}
	}
	return u.nbytes, nil
}

func marshalToWriter(skip int, w io.Writer, vals ...interface{}) (int, error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	m := &marshaller{context: &context{caller: caller, mode: "marshal", total: len(vals)}, w: w}
	return m.marshal(vals...)
}

// MarshalToWriter marshals vals to w in the TPM wire format, according to the rules specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to the zero value for the pointed to type, unless
// the pointer is to a sized structure (a struct field with the 'tpm2:"sized"` tag pointing to another struct), in which case
// a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does not complete successfully, it will return an error and
// the number of bytes written.
//
// This function only returns an error if a sized value (sized buffer, sized structure or list) is too large for its corresponding
// size field, or if the supplied io.Writer returns an error.
func MarshalToWriter(w io.Writer, vals ...interface{}) (int, error) {
	return marshalToWriter(2, w, vals...)
}

// MustMarshalToWriter is the same as MarshalToWriter, except that it panics if it encounters an error.
func MustMarshalToWriter(w io.Writer, vals ...interface{}) int {
	n, err := marshalToWriter(2, w, vals...)
	if err != nil {
		panic(err)
	}
	return n
}

func marshalToBytes(skip int, vals ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := marshalToWriter(skip+1, buf, vals...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalToBytes marshals vals to TPM wire format, according to the rules specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to the zero value for the pointed to type, unless
// the pointer is to a sized structure (a struct field with the 'tpm2:"sized"` tag pointing to another struct), in which case
// a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does not complete successfully, it will return an error and
// the number of bytes written.
//
// This function only returns an error if a sized value (sized buffer, sized structure or list) is too large for its corresponding
// size field.
func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	return marshalToBytes(2, vals...)
}

// MustMarshalToBytes is the same as MarshalToBytes, except that it panics if it encounters an error.
func MustMarshalToBytes(vals ...interface{}) []byte {
	b, err := marshalToBytes(2, vals...)
	if err != nil {
		panic(err)
	}
	return b
}

func unmarshalFromReader(skip int, r io.Reader, vals ...interface{}) (int, error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	u, err := makeUnmarshaller(&context{caller: caller, mode: "unmarshal", total: len(vals)}, r)
	if err != nil {
		return 0, err
	}
	return u.unmarshal(vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from r to vals, according to the rules specified in the package
// description. The values supplied to this function must be pointers to the destination values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then memory is allocated for the values and the pointer
// is initialized accordingly, unless the pointer is to a sized structure (a struct field with the 'tpm2:"sized"' tag pointing
// to another struct) and the values being unmarshalled has a zero size, in which case the pointer is not initialized. If
// a pointer is already initialized by the caller, then this function will unmarshal to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already allocated a slice that has a large enough capacity
// to hold the unmarshalled values, in which case the already allocated slice will be used and its length set accordingly.
//
// This can unmarshal raw slices (those without a corresponding size or length fields, represented by the RawBytes type or
// a slice value referenced from a struct field with the 'tpm2:"raw"' tag), but the caller must pre-allocate a slice of the
// correct size first. This function cannot allocate a slice because it doesn't have a way to determine the size to allocate.
//
// The number of bytes read from r are returned. If this function does not complete successfully, it will return an error and
// the number of bytes read. In this case, partial results may have been unmarshalled to the supplied destination values.
func UnmarshalFromReader(r io.Reader, vals ...interface{}) (int, error) {
	return unmarshalFromReader(2, r, vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from b to vals, according to the rules specified in the package
// description. The values supplied to this function must be pointers to the destination values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then memory is allocated for the value and the pointer
// is initialized accordingly, unless the pointer is to a sized structure (a struct field with the 'tpm2:"sized"' tag pointing
// to another struct) and the value being unmarshalled has a zero size, in which case the pointer is not initialized. If
// a pointer is already initialized by the caller, then this function will unmarshal to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already allocated a slice that has a large enough capacity
// to hold the unmarshalled values, in which case the already allocated slice will be used and its length set accordingly.
//
// This can unmarshal raw slices (those without a corresponding size or length fields, represented by the RawBytes type or
// a slice value referenced from a struct field with the 'tpm2:"raw"' tag), but the caller must pre-allocate a slice of the
// correct size first. This function cannot allocate a slice because it doesn't have a way to determine the size to allocate.
//
// The number of bytes consumed from b are returned. If this function does not complete successfully, it will return an error and
// the number of bytes consumed. In this case, partial results may have been unmarshalled to the supplied destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	return unmarshalFromReader(2, buf, vals...)
}

func copyValue(skip int, dst, src interface{}) error {
	var wrappedDst *wrappedValue
	switch w := dst.(type) {
	case *wrappedValue:
		wrappedDst = &wrappedValue{value: w.value, opts: w.opts}
	default:
		wrappedDst = &wrappedValue{value: dst}

	}

	dstV := reflect.ValueOf(wrappedDst.value)
	if dstV.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(wrappedDst.value)))
	}
	if dstV.IsNil() {
		panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", dstV.Type()))
	}

	isInterface := false
	if dstV.Elem().Kind() == reflect.Interface {
		if !reflect.TypeOf(src).Implements(dstV.Elem().Type()) {
			panic(fmt.Sprintf("type %s does not implement destination interface %s", reflect.TypeOf(src), dstV.Elem().Type()))
		}
		wrappedDst.value = reflect.New(reflect.TypeOf(src)).Interface()
		isInterface = true
	}

	buf := new(bytes.Buffer)
	if _, err := marshalToWriter(skip+1, buf, src); err != nil {
		return err
	}
	if _, err := unmarshalFromReader(skip+1, buf, wrappedDst); err != nil {
		return err
	}

	if isInterface {
		dstV.Elem().Set(reflect.ValueOf(wrappedDst.value).Elem())
	}

	return nil
}

// CopyValue copies the value of src to dst. The destination must be a pointer to the actual
// destination value. This works by serializing the source value in the TPM wire format
// and the deserializing it again into the destination.
//
// This will return an error for any reason that would cause MarshalToBytes or
// UnmarshalFromBytes to return an error.
func CopyValue(dst, src interface{}) error {
	return copyValue(2, dst, src)
}

// MustCopyValue is the same as CopyValue except that it panics if it encounters an error.
func MustCopyValue(dst, src interface{}) {
	if err := copyValue(2, dst, src); err != nil {
		panic(err)
	}
}
