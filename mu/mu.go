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
	"reflect"
	"runtime"
	"strings"
)

const (
	// maxListLength is the maximum theoretical length of a TPML type that can be
	// supported, although no lists are this long in practise. TPML types have a
	// uint32 length field and are represented in go as slices. The length of a
	// slice is represented as a go int, which is either 32-bit or 64-bit, so set
	// the maximum to the highest number that can be represented by an int32
	maxListLength = math.MaxInt32
)

var (
	sized1BytesType        reflect.Type = reflect.TypeOf(Sized1Bytes(nil))
	customMarshallerType   reflect.Type = reflect.TypeOf((*customMarshallerIface)(nil)).Elem()
	customUnmarshallerType reflect.Type = reflect.TypeOf((*customUnmarshallerIface)(nil)).Elem()
	rawBytesType           reflect.Type = reflect.TypeOf(RawBytes(nil))
	unionType              reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
)

// InvalidSelectorError is returned as a wrapped error during marshalling and unmarshalling
// when a union type indicates that a selector value is invalid. It may also be returned during
// marshalling if a union type has a content type that is inconsistent with the selector.
type InvalidSelectorError struct {
	Selector any
}

func (e *InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

type customMarshallerIface interface {
	Marshal(w io.Writer) error
}

type customUnmarshallerIface interface {
	Unmarshal(r io.Reader) error
}

// CustomMarshaller is implemented by types that require custom marshalling
// behaviour because they are non-standard and not directly supported by this
// package.
//
// If the implementation makes a recursive call in to this package, it should
// return errors from any recursive call without wrapping. This allows the full
// context of the error to be surfaced from the originating call.
type CustomMarshaller interface {
	// Marshal should serialize the value to the supplied writer.
	// The implementation of this should take a value receiver, but if
	// it takes a pointer receiver then the value must be addressable.
	Marshal(w io.Writer) error

	// Unmarshal should unserialize the value from the supplied reader.
	// The implementation of this should take a pointer receiver.
	Unmarshal(r io.Reader) error
}

var _ CustomMarshaller = struct {
	customMarshallerIface
	customUnmarshallerIface
}{}

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a
// size field. The slice must be pre-allocated to the correct length by the caller during
// unmarshalling.
type RawBytes []byte

// Sized1Bytes is a special byte slice which is marshalled and unmarhalled with a
// single byte size field. This is to faciliate the TPMS_PCR_SELECT type, which
// looks like any other variable sized type (TPML and TPM2B types) with a size
// field and variable sized payload, only TPMS_PCR_SELECT has a single byte size
// field.
type Sized1Bytes []byte

type rawType[T ~[]E, E any] struct {
	Value T `tpm2:"raw"`
}

// MakeRaw converts the supplied slice to a raw type so that it is marshalled and
// unmarshalled without a size or length field.
func MakeRaw[T ~[]E, E any](val T) *rawType[T, E] {
	return &rawType[T, E]{Value: val}
}

type sizedType[P *T, T *E, E any] struct {
	Value P `_tpm2:"_sized"`
}

// MakeSizedSource converts the supplied pointer to a sized type so that it is
// marshalled as a TPM2B type with a size field.
func MakeSizedSource[P *T, T *E, E any](val T) sizedType[P, T, E] {
	return sizedType[P, T, E]{Value: &val}
}

// MakeSizedDest converts the supplied pointer to a sized type so that it is
// unmarshalled as a TPM2B type with a size field.
func MakeSizedDest[P *T, T *E, E any](val P) *sizedType[P, T, E] {
	return &sizedType[P, T, E]{Value: val}
}

type unionMarshalIface interface {
	SelectMarshal(selector any) any
}

type unionUnmarshalIface interface {
	SelectUnmarshal(selector any) any
}

// Union is implemented by go types that correspond to TPMU prefixed TPM types.
// A struct that contains a union member automatically becomes a tagged union. The
// selector field is the first member of the tagged union, unless overridden with the
// `tpm2:"selector:<field_name>"` tag.
//
// Go doesn't have support for unions - TPMU types are implemented by any type that
// implements this interface. They should use the [UnionContents] helper for storing
// the value of the union.
type Union interface {
	// SelectMarshal is called by this package to map the supplied selector
	// value to a union value.
	//
	// If nil is returned, this is interpreted as a [InvalidSelectorError] error.
	SelectMarshal(selector any) any

	// SelectUnmarshal is called by this package to map the supplied selector
	// value to a pointer to a union value.
	//
	// If nil is returned, this is interpreted as a [InvalidSelectorError] error.
	SelectUnmarshal(selector any) any
}

var _ Union = struct {
	unionMarshalIface
	unionUnmarshalIface
}{}

type containerNode struct {
	value  reflect.Value
	custom bool
	index  int
	sized  bool
	entry  [1]uintptr
}

type containerStack []containerNode

func (s containerStack) push(node containerNode) containerStack {
	return append(s, node)
}

func (s containerStack) pop() containerStack {
	return s[:len(s)-1]
}

func (s containerStack) top() *containerNode {
	return &s[len(s)-1]
}

func (s containerStack) String() string {
	str := new(bytes.Buffer)
	str.WriteString("=== BEGIN STACK ===\n")
	for i := len(s) - 1; i >= 0; i-- {
		switch {
		case s[i].custom && s[i].entry != [1]uintptr{0}:
			frames := runtime.CallersFrames(s[i].entry[:])
			frame, _ := frames.Next()
			fmt.Fprintf(str, "... %s location %s:%d, argument %d\n", s[i].value.Type(), frame.File, frame.Line, s[i].index)
		case s[i].custom:
			fmt.Fprintf(str, "... %s\n", s[i].value.Type())
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

	entry    [1]uintptr
	stack    containerStack
	leafType reflect.Type
	err      error
}

func (e *Error) Error() string {
	s := new(bytes.Buffer)
	fmt.Fprintf(s, "cannot %s argument %d whilst processing element of type %s: %v", e.Op, e.Index, e.leafType, e.err)
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
// If the returned type implements the [CustomMarshaller] and
// [CustomUnmarshaller] interfaces, the returned index corresponds to
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

type fatalError struct {
	index int
	entry [1]uintptr
	stack containerStack
	err   interface{}
}

func (e *fatalError) Error() string {
	s := new(bytes.Buffer)
	fmt.Fprintf(s, "%v", e.err)
	if len(e.stack) > 0 {
		fmt.Fprintf(s, "\n\n%s", e.stack)
	}
	return s.String()
}

type options struct {
	selector string
	sized    bool
	raw      bool
	ignore   bool
	sized1   bool

	indirectSized bool
}

func (o *options) enterSizedType(v reflect.Value) (exit func()) {
	orig := *o
	o.sized = false
	if v.Kind() == reflect.Slice {
		o.raw = true
	}
	return func() {
		*o = orig
	}
}

func (o *options) enterIndirectSizedType() (exit func()) {
	orig := *o
	o.indirectSized = false
	o.sized = true
	return func() {
		*o = orig
	}
}

func (o *options) parseFromStructField(f reflect.StructField) {
	s := f.Tag.Get("tpm2")
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "selector:"):
			o.selector = part[9:]
		case part == "sized":
			o.sized = true
		case part == "raw":
			o.raw = true
		case part == "ignore":
			o.ignore = true
		case part == "sized1":
			o.sized1 = true
		}
	}
	s = f.Tag.Get("_tpm2")
	for _, part := range strings.Split(s, ",") {
		switch {
		case part == "_sized":
			o.indirectSized = true
		}
	}
}

func newOptionsFromStructField(f reflect.StructField) (out *options) {
	out = new(options)
	out.parseFromStructField(f)
	return out
}

// kind indicates the TPM type class associated with a Go type
type kind int

const (
	// kindUnsupported indicates that a go type has no corresponding
	// TPM type class.
	kindUnsupported kind = iota

	// kindPrimitive indicates that a go type corresponds to one
	// of the primitive TPM types (UINT8, BYTE, INT8, BOOL, UINT16,
	// INT16, UINT32, INT32, UINT64, INT64, TPM_ALG_ID, any TPMA_
	// prefixed type).
	kindPrimitive

	// kindSized indicates that a go type corresponds to a
	// TPM2B prefixed TPM type.
	kindSized

	// kindList indicates that a go type corresponds to a
	// TPML prefixed TPM type.
	kindList

	// kindStruct indicates that a go type corresponds to a
	// TPMS or TPMT prefixed TPM type.
	kindStruct

	// kindUnion indicates that a go type corresponds to a
	// TPMU prefixed TPM type.
	kindUnion

	// kindCustom correponds to a go type that defines its own
	// marshalling behaviour.
	kindCustom

	// kindRawList corresponds to a go slice that is marshalled
	// without a length field. It behaves like a sequence of
	// individual values.
	kindRawList

	// kindRawBytes corresponds to a byte slice that is marshalled
	// without a size field.
	kindRawBytes

	// kindSized1Bytes indicates that a go type corresponds to
	// a variable sized byte slice with a single byte size field,
	// and is a special type used to support TPMS_PCR_SELECT.
	kindSized1Bytes

	kindNeedsDeref

	kindIndirectSized

	kindIgnore
)

func isCustom(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Implements(customMarshallerType) && t.Implements(customUnmarshallerType)
}

func isUnion(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Elem().Kind() == reflect.Struct && t.Implements(unionType)
}

func classifyKind(t reflect.Type, o *options) (kind, error) {
	if o.ignore {
		return kindIgnore, nil
	}

	sizeSpecifiers := 0
	if o.sized {
		sizeSpecifiers += 1
	}
	if o.raw {
		sizeSpecifiers += 1
	}
	if o.sized1 {
		sizeSpecifiers += 1
	}
	if o.indirectSized {
		sizeSpecifiers += 1
	}
	if sizeSpecifiers > 1 {
		return kindUnsupported, errors.New(`only one of "sized", "raw" and "sized1" may be specified`)
	}

	if t.Kind() != reflect.Ptr && isCustom(t) {
		if sizeSpecifiers != 0 || o.selector != "" {
			return kindUnsupported, errors.New("invalid options for custom type")
		}
		return kindCustom, nil
	}

	switch t.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if sizeSpecifiers != 0 || o.selector != "" {
			return kindUnsupported, errors.New("invalid options for primitive type")
		}
		return kindPrimitive, nil
	case reflect.Ptr:
		switch {
		case o.indirectSized:
			return kindIndirectSized, nil
		case o.sized:
			return kindSized, nil
		default:
			return kindNeedsDeref, nil
		}
	case reflect.Slice:
		switch {
		case o.sized || o.selector != "" || o.indirectSized:
			return kindUnsupported, errors.New("invalid options for slice type")
		case o.raw && t == sized1BytesType:
			return kindUnsupported, errors.New(`"raw" option is invalid with Sized1Bytes type`)
		case o.sized && t.Elem().Kind() != reflect.Uint8:
			return kindUnsupported, errors.New(`"sized1" option is only valid with byte slices`)
		case t == sized1BytesType || o.sized1:
			return kindSized1Bytes, nil
		case t == rawBytesType || (o.raw && t.Elem().Kind() == reflect.Uint8):
			return kindRawBytes, nil
		case o.raw:
			return kindRawList, nil
		case t.Elem().Kind() == reflect.Uint8:
			return kindSized, nil
		default:
			return kindList, nil
		}
	case reflect.Struct:
		if sizeSpecifiers > 0 {
			return kindUnsupported, errors.New("invalid options for struct type")
		}

		var taggedUnion bool
		var hasUnexported bool

		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				hasUnexported = true
			}
			if isUnion(f.Type) {
				taggedUnion = true
			}
		}

		if isUnion(t) {
			if taggedUnion {
				return kindUnsupported, errors.New("struct type cannot represent both a union and tagged union")
			}
			return kindUnion, nil
		}

		switch {
		case hasUnexported:
			// structs with unexported fields are unsupported
			return kindUnsupported, errors.New("struct type with unexported fields")
		case o.selector != "":
			return kindUnsupported, errors.New(`"selector" option is invalid with struct types that don't represent unions`)
		}

		return kindStruct, nil
	case reflect.Array:
		switch {
		case sizeSpecifiers != 0 || o.selector != "":
			return kindUnsupported, errors.New("invalid options for array type")
		case t.Elem().Kind() != reflect.Uint8:
			return kindUnsupported, errors.New("unsupported array type")
		}
		return kindPrimitive, nil
	default:
		return kindUnsupported, fmt.Errorf("unsupported kind: %v", t.Kind())
	}
}

// IsSized indicates that the supplied value is a TPM2B type. This will
// automatically dereference pointer types.
func IsSized(i interface{}) bool {
	t := reflect.TypeOf(i)
	o := new(options)

	for {
		k, err := classifyKind(t, o)
		switch {
		case err != nil:
			return false
		case k == kindNeedsDeref:
			t = t.Elem()
		case k == kindIndirectSized:
			t = t.Elem()
			o.enterIndirectSizedType()
		case k == kindStruct:
			if t.NumField() != 1 {
				return false
			}
			f := t.Field(0)
			t = f.Type
			o.parseFromStructField(f)
		default:
			return k == kindSized
		}
	}
}

type context struct {
	caller [1]uintptr     // address of the function calling into the public API
	mode   string         // marshal or unmarshal
	index  int            // current argument index
	stack  containerStack // type stack for this context

	parent *context // parent context associated with a call from a custom type
}

func (c *context) checkInfiniteRecursion(v reflect.Value) {
	ctx := c
	for ctx != nil {
		for i := len(ctx.stack) - 1; i >= 0; i-- {
			n := ctx.stack[i]
			if n.value.Kind() == reflect.Slice || (n.value.Kind() == reflect.Struct && (n.sized || isUnion(n.value.Type()))) {
				return
			}
			if n.value.Type() == v.Type() {
				panic(fmt.Sprintf("infinite recursion detected when processing type %s", v.Type()))
			}
		}
		ctx = ctx.parent
	}
}

func (c *context) enterStructField(s reflect.Value, i int, opts *options) (exit func()) {
	c.checkInfiniteRecursion(s)
	c.stack = c.stack.push(containerNode{value: s, index: i, sized: opts != nil && opts.sized})

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

func (c *context) unionSelectorValue(u reflect.Value, opts *options) any {
	if len(c.stack) == 0 || c.stack.top().value.Kind() != reflect.Struct {
		panic(fmt.Sprintf("union type %s is not inside a struct", u.Type()))
	}

	var selectorVal reflect.Value
	if opts.selector == "" {
		selectorVal = c.stack.top().value.Field(0)
	} else {
		selectorVal = c.stack.top().value.FieldByName(opts.selector)
		if !selectorVal.IsValid() {
			panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field",
				opts.selector, u.Type()))
		}
	}

	return selectorVal.Interface()
}

func (c *context) enterCustomType(v reflect.Value) (exit func()) {
	c.checkInfiniteRecursion(v)
	c.stack = c.stack.push(containerNode{value: v, custom: true})

	return func() {
		c.stack = c.stack.pop()
	}
}

func (c *context) wrapOrNewError(value reflect.Value, err error) error {
	muErr, isMuErr := err.(*Error)
	if !isMuErr {
		return c.newError(value, err)
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)

	stack = append(stack, containerNode{value: value, custom: true, index: muErr.Index, entry: muErr.entry})

	return &Error{
		Index:    c.index,
		Op:       c.mode,
		entry:    c.caller,
		stack:    append(stack, muErr.stack...),
		leafType: muErr.leafType,
		err:      muErr.err}
}

func (c *context) newError(value reflect.Value, err error) error {
	if err == io.EOF {
		// All io.EOF is unexpected
		err = io.ErrUnexpectedEOF
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)

	return &Error{
		Index:    c.index,
		Op:       c.mode,
		entry:    c.caller,
		stack:    stack,
		leafType: value.Type(),
		err:      err}
}

func (c *context) wrapFatal(err interface{}) *fatalError {
	f, ok := err.(*fatalError)
	if !ok {
		return &fatalError{
			index: c.index,
			entry: c.caller,
			stack: c.stack,
			err:   err}
	}

	stack := make(containerStack, len(c.stack))
	copy(stack, c.stack)
	stack.top().index = f.index
	stack.top().entry = f.entry

	return &fatalError{
		index: c.index,
		entry: c.caller,
		stack: append(stack, f.stack...),
		err:   f.err}
}

type marshaller struct {
	*context
	w      io.Writer
	nbytes int
}

func newMarshaller(caller [1]uintptr, w io.Writer) *marshaller {
	var parent *context
	if m, ok := w.(*marshaller); ok {
		parent = m.context
	}
	return &marshaller{
		context: &context{
			caller: caller,
			mode:   "marshal",
			parent: parent},
		w: w}
}

func (m *marshaller) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.nbytes += n
	return
}

func (m *marshaller) marshalSized(v reflect.Value, opts *options) error {
	if v.IsNil() {
		if err := binary.Write(m, binary.BigEndian, uint16(0)); err != nil {
			return m.newError(v, err)
		}
		return nil
	}

	exit := opts.enterSizedType(v)
	defer exit()

	tmpBuf := new(bytes.Buffer)
	sm := &marshaller{context: m.context, w: tmpBuf}
	if err := sm.marshalValue(v, opts); err != nil {
		return err
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return m.newError(v, fmt.Errorf("sized value size of %d is larger than 2^16-1", tmpBuf.Len()))
	}
	if err := binary.Write(m, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return m.newError(v, err)
	}
	if _, err := tmpBuf.WriteTo(m); err != nil {
		return m.newError(v, err)
	}
	return nil
}

func (m *marshaller) marshalIndirectSized(v reflect.Value, opts *options) error {
	exit := opts.enterIndirectSizedType()
	defer exit()

	return m.marshalPtr(v, opts)
}

func (m *marshaller) marshalSized1Bytes(v reflect.Value) error {
	if v.Len() > math.MaxUint8 {
		return m.newError(v, fmt.Errorf("value size of %d is larger than 2^8-1", v.Len()))
	}
	if err := binary.Write(m, binary.BigEndian, uint8(v.Len())); err != nil {
		return m.newError(v, err)
	}
	return m.marshalRawBytes(v)
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

func (m *marshaller) marshalRawBytes(v reflect.Value) error {
	if _, err := m.Write(v.Bytes()); err != nil {
		return m.newError(v, err)
	}
	return nil
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
		return m.newError(v, err)
	}
	return nil
}

func (m *marshaller) marshalList(v reflect.Value) error {
	if v.Len() > maxListLength {
		return m.newError(v, fmt.Errorf("slice length of %d is out of range", v.Len()))
	}

	// Marshal length field
	if err := binary.Write(m, binary.BigEndian, uint32(v.Len())); err != nil {
		return m.newError(v, err)
	}

	return m.marshalRawList(v)
}

func (m *marshaller) marshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		opts := newOptionsFromStructField(v.Type().Field(i))
		exit := m.enterStructField(v, i, opts)
		if err := m.marshalValue(v.Field(i), opts); err != nil {
			exit()
			return err
		}
		exit()
	}

	return nil
}

func (m *marshaller) marshalUnion(v reflect.Value, opts *options) error {
	selectorVal := m.unionSelectorValue(v, opts)
	elem := v.Interface().(unionMarshalIface).SelectMarshal(selectorVal)
	if elem == nil {
		return m.newError(v, &InvalidSelectorError{selectorVal})
	}

	return m.marshalValue(reflect.ValueOf(elem), nil)
}

func (m *marshaller) marshalCustom(v reflect.Value) error {
	if !v.Type().Implements(customMarshallerType) {
		// support Marshal() implementations that take a pointer receiver.
		if !v.CanAddr() {
			panic(fmt.Sprintf("custom type %s needs to be addressable", v.Type()))
		}
		v = v.Addr()
	}

	exit := m.enterCustomType(v)

	if err := v.Interface().(customMarshallerIface).Marshal(m); err != nil {
		exit()
		return m.wrapOrNewError(v, err)
	}

	exit()
	return nil
}

func (m *marshaller) marshalValue(v reflect.Value, opts *options) error {
	if opts == nil {
		var def options
		opts = &def
	}

	kind, err := classifyKind(v.Type(), opts)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal unsupported type %s (%v)", v.Type(), err))
	}

	switch kind {
	case kindPrimitive:
		return m.marshalPrimitive(v)
	case kindSized:
		return m.marshalSized(v, opts)
	case kindList:
		return m.marshalList(v)
	case kindStruct:
		return m.marshalStruct(v)
	case kindUnion:
		return m.marshalUnion(v, opts)
	case kindCustom:
		return m.marshalCustom(v)
	case kindRawList:
		return m.marshalRawList(v)
	case kindRawBytes:
		return m.marshalRawBytes(v)
	case kindSized1Bytes:
		return m.marshalSized1Bytes(v)
	case kindNeedsDeref:
		return m.marshalPtr(v, opts)
	case kindIndirectSized:
		return m.marshalIndirectSized(v, opts)
	case kindIgnore:
		return nil
	}

	panic("unhandled kind")
}

func (m *marshaller) marshal(vals ...interface{}) (int, error) {
	defer func() {
		if err := recover(); err != nil {
			panic(m.wrapFatal(err))
		}
	}()

	for i, v := range vals {
		m.index = i
		if err := m.marshalValue(reflect.ValueOf(v), nil); err != nil {
			return m.nbytes, err
		}
	}
	return m.nbytes, nil
}

type unmarshaller struct {
	*context
	r      io.Reader
	nbytes int
}

func newUnmarshaller(caller [1]uintptr, r io.Reader) *unmarshaller {
	var parent *context
	if u, ok := r.(*unmarshaller); ok {
		parent = u.context
	}
	return &unmarshaller{
		context: &context{
			caller: caller,
			mode:   "unmarshal",
			parent: parent},
		r: r}
}

func (u *unmarshaller) Read(p []byte) (n int, err error) {
	n, err = u.r.Read(p)
	u.nbytes += n
	return
}

func (u *unmarshaller) unmarshalSized(v reflect.Value, opts *options) error {
	var size uint16
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return u.newError(v, err)
	}

	// v is either:
	// - a pointer kind, in which case it is a pointer to a struct. This
	//   is the sized structure case.
	// - a slice kind, in which case the slice is always a byte slice. This
	//   is the sized buffer case.
	switch {
	case size == 0:
		// zero sized structure. Clear the pointer if it was pre-set and
		// then return early.
		v.Set(reflect.Zero(v.Type()))
		return nil
	case v.Kind() == reflect.Slice && (v.IsNil() || v.Cap() < int(size)):
		// sized buffer with no pre-allocated buffer or a pre-allocated
		// buffer that isn't large enough. Allocate a new one.
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	case v.Kind() == reflect.Slice:
		// sized buffer with pre-allocated buffer that is large enough.
		v.SetLen(int(size))
	}

	exit := opts.enterSizedType(v)
	defer exit()

	su := &unmarshaller{context: u.context, r: io.LimitReader(u, int64(size))}
	return su.unmarshalValue(v, opts)
}

func (u *unmarshaller) unmarshalIndirectSized(v reflect.Value, opts *options) error {
	exit := opts.enterIndirectSizedType()
	defer exit()

	return u.unmarshalPtr(v, opts)
}

func (u *unmarshaller) unmarshalSized1Bytes(v reflect.Value) error {
	var size uint8
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return u.newError(v, err)
	}

	switch {
	case size == 0:
		// zero sized. Set the slice to nil if it was pre-set.
		v.Set(reflect.Zero(v.Type()))
		return nil
	case v.IsNil() || v.Cap() < int(size):
		// No pre-allocated slice or one that isn't big enough.
		// Allocate a new one.
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	default:
		// Reuse the pre-allocated slice.
		v.SetLen(int(size))
	}

	return u.unmarshalRawBytes(v)
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

func (u *unmarshaller) unmarshalRawBytes(v reflect.Value) error {
	if _, err := io.ReadFull(u, v.Bytes()); err != nil {
		return u.newError(v, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalPtr(v reflect.Value, opts *options) error {
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	return u.unmarshalValue(v.Elem(), opts)
}

func (u *unmarshaller) unmarshalPrimitive(v reflect.Value) error {
	if err := binary.Read(u, binary.BigEndian, v.Addr().Interface()); err != nil {
		return u.newError(v, err)
	}
	return nil
}

func (u *unmarshaller) unmarshalList(v reflect.Value) error {
	// Unmarshal the length
	var length uint32
	if err := binary.Read(u, binary.BigEndian, &length); err != nil {
		return u.newError(v, err)
	}

	switch {
	case length > maxListLength:
		return u.newError(v, fmt.Errorf("list length of %d is out of range", length))
	case v.IsNil() && length > 0:
		// Try to reuse the existing slice, although it may be
		// reallocated later if the capacity isn't large enough
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
	case length == 0:
		// Clear any existing slice
		v.Set(reflect.Zero(v.Type()))
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
		opts := newOptionsFromStructField(v.Type().Field(i))
		exit := u.enterStructField(v, i, opts)
		if err := u.unmarshalValue(v.Field(i), opts); err != nil {
			exit()
			return err
		}
		exit()
	}
	return nil
}

func (u *unmarshaller) unmarshalUnion(v reflect.Value, opts *options) error {
	selectorVal := u.unionSelectorValue(v, opts)
	elemPtr := v.Addr().Interface().(unionUnmarshalIface).SelectUnmarshal(selectorVal)
	if elemPtr == nil {
		return u.newError(v, &InvalidSelectorError{selectorVal})
	}

	return u.unmarshalValue(reflect.ValueOf(elemPtr).Elem(), nil)
}

func (u *unmarshaller) unmarshalCustom(v reflect.Value) error {
	if !v.CanAddr() {
		panic(fmt.Sprintf("custom type %s needs to be addressable", v.Type()))
	}

	exit := u.enterCustomType(v)

	if err := v.Addr().Interface().(customUnmarshallerIface).Unmarshal(u); err != nil {
		exit()
		return u.wrapOrNewError(v, err)
	}

	exit()
	return nil
}

func (u *unmarshaller) unmarshalValue(v reflect.Value, opts *options) error {
	if opts == nil {
		var def options
		opts = &def
	}

	kind, err := classifyKind(v.Type(), opts)
	if err != nil {
		panic(fmt.Sprintf("cannot unmarshal unsupported type %s (%v)", v.Type(), err))
	}

	switch kind {
	case kindPrimitive:
		return u.unmarshalPrimitive(v)
	case kindSized:
		return u.unmarshalSized(v, opts)
	case kindList:
		return u.unmarshalList(v)
	case kindStruct:
		return u.unmarshalStruct(v)
	case kindUnion:
		return u.unmarshalUnion(v, opts)
	case kindCustom:
		return u.unmarshalCustom(v)
	case kindRawList:
		_, err = u.unmarshalRawList(v.Slice(0, 0), v.Len())
		return err
	case kindRawBytes:
		return u.unmarshalRawBytes(v)
	case kindSized1Bytes:
		return u.unmarshalSized1Bytes(v)
	case kindNeedsDeref:
		return u.unmarshalPtr(v, opts)
	case kindIndirectSized:
		return u.unmarshalIndirectSized(v, opts)
	case kindIgnore:
		return nil
	}

	panic("unhandled kind")
}

func (u *unmarshaller) unmarshal(vals ...interface{}) (int, error) {
	defer func() {
		if err := recover(); err != nil {
			panic(u.wrapFatal(err))
		}
	}()

	for i, v := range vals {
		u.index = i

		val := reflect.ValueOf(v)
		if val.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(v)))
		}

		if val.IsNil() {
			panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", val.Type()))
		}

		if err := u.unmarshalValue(val.Elem(), nil); err != nil {
			return u.nbytes, err
		}
	}
	return u.nbytes, nil
}

func marshalToWriter(skip int, w io.Writer, vals ...interface{}) (int, error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	m := newMarshaller(caller, w)
	return m.marshal(vals...)
}

// MarshalToWriter marshals vals to w in the TPM wire format, according
// to the rules specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to
// the zero value for the pointed to type, unless the pointer is to a
// sized structure (a struct field with the 'tpm2:"sized"` tag), in which
// case a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes written.
//
// This function only returns an error if a sized value (sized buffer,
// sized structure or list) is too large for its corresponding size field,
// or if the supplied io.Writer returns an error.
func MarshalToWriter(w io.Writer, vals ...interface{}) (int, error) {
	return marshalToWriter(2, w, vals...)
}

// MustMarshalToWriter is the same as [MarshalToWriter], except that it panics if it encounters an error.
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

// MarshalToBytes marshals vals to TPM wire format, according to the rules
// specified in the package description.
//
// Pointers are automatically dereferenced. Nil pointers are marshalled to
// the zero value for the pointed to type, unless the pointer is to a
// sized structure (a struct field with the 'tpm2:"sized"` tag), in which
// case a value of zero size is marshalled.
//
// The number of bytes written to w are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes written.
//
// This function only returns an error if a sized value (sized buffer,
// sized structure or list) is too large for its corresponding size field.
func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	return marshalToBytes(2, vals...)
}

// MustMarshalToBytes is the same as [MarshalToBytes], except that it panics if it encounters an error.
func MustMarshalToBytes(vals ...interface{}) []byte {
	b, err := marshalToBytes(2, vals...)
	if err != nil {
		panic(err)
	}
	return b
}

func unmarshalFromReader(skip int, r io.Reader, vals ...interface{}) (n int, err error) {
	var caller [1]uintptr
	runtime.Callers(skip+1, caller[:])

	u := newUnmarshaller(caller, r)
	return u.unmarshal(vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from r to
// vals, according to the rules specified in the package description. The
// values supplied to this function must be pointers to the destination
// values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then
// memory is allocated for the value and the pointer is initialized
// accordingly, unless the pointer is to a sized structure (a struct field
// with the 'tpm2:"sized"' tag) and the value being unmarshalled has a
// zero size, in which case the pointer is cleared. If a pointer is
// already initialized by the caller, then this function will unmarshal
// to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already
// allocated a slice in which case it will be used if it has a large
// enough capacity. Zero length slices are unmarshalled as nil.
//
// This can unmarshal raw slices (those without a corresponding size or
// length fields, represented by the [RawBytes] type or a slice value
// referenced from a struct field with the 'tpm2:"raw"' tag), but the
// caller must pre-allocate a slice of the correct size first. This
// function cannot allocate a slice because it doesn't have a way to
// determine the size to allocate.
//
// The number of bytes read from r are returned. If this function does
// not complete successfully, it will return an error and the number of
// bytes read. In this case, partial results may have been unmarshalled
// to the supplied destination values.
func UnmarshalFromReader(r io.Reader, vals ...interface{}) (int, error) {
	return unmarshalFromReader(2, r, vals...)
}

// UnmarshalFromReader unmarshals data in the TPM wire format from b to
// vals, according to the rules specified in the package description.
// The values supplied to this function must be pointers to the
// destination values.
//
// Pointers are automatically dererefenced. If a pointer is nil, then
// memory is allocated for the value and the pointer is initialized
// accordingly, unless the pointer is to a sized structure (a struct field
// with the 'tpm2:"sized"' tag) and the value being unmarshalled has a
// zero size, in which case the pointer is cleared. If a pointer is
// already initialized by the caller, then this function will unmarshal
// to the already allocated memory.
//
// Slices are allocated automatically, unless the caller has already
// allocated a slice in which case it will be used if it has a large
// enough capacity. Zero length slices are unmarshalled as nil.
//
// This can unmarshal raw slices (those without a corresponding size or
// length fields, represented by the [RawBytes] type or a slice value
// referenced from a struct field with the 'tpm2:"raw"' tag), but the
// caller must pre-allocate a slice of the correct size first. This
// function cannot allocate a slice because it doesn't have a way to
// determine the size to allocate.
//
// The number of bytes consumed from b are returned. If this function
// does not complete successfully, it will return an error and the number
// of bytes consumed. In this case, partial results may have been
// unmarshalled to the supplied destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	return unmarshalFromReader(2, buf, vals...)
}

func copyValue(skip int, dst, src interface{}) error {
	dstV := reflect.ValueOf(dst)
	if dstV.Kind() != reflect.Ptr {
		panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", reflect.TypeOf(dst)))
	}
	if dstV.IsNil() {
		panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", dstV.Type()))
	}

	dstLocal := dst

	isInterface := false
	if dstV.Elem().Kind() == reflect.Interface {
		if !reflect.TypeOf(src).Implements(dstV.Elem().Type()) {
			panic(fmt.Sprintf("type %s does not implement destination interface %s", reflect.TypeOf(src), dstV.Elem().Type()))
		}
		dstLocal = reflect.New(reflect.TypeOf(src)).Interface()
		isInterface = true
	}

	buf := new(bytes.Buffer)
	if _, err := marshalToWriter(skip+1, buf, src); err != nil {
		return err
	}
	if _, err := unmarshalFromReader(skip+1, buf, dstLocal); err != nil {
		return err
	}

	if isInterface {
		dstV.Elem().Set(reflect.ValueOf(dstLocal).Elem())
	}

	return nil
}

// CopyValue copies the value of src to dst. The destination must be a
// pointer to the actual destination value. This works by serializing the
// source value in the TPM wire format and the deserializing it again into
// the destination.
//
// This will return an error for any reason that would cause [MarshalToBytes] or
// [UnmarshalFromBytes] to return an error.
func CopyValue(dst, src interface{}) error {
	return copyValue(2, dst, src)
}

// MustCopyValue is the same as [CopyValue] except that it panics if it encounters an error.
func MustCopyValue(dst, src interface{}) {
	if err := copyValue(2, dst, src); err != nil {
		panic(err)
	}
}

// IsValid determines whether the supplied value is representable by
// the TPM wire format. It returns false if the type would cause a panic
// during marshalling or unmarshalling.
func IsValid(v interface{}) (valid bool) {
	defer func() {
		if err := recover(); err != nil {
			valid = false
		}
	}()

	var d interface{}
	if err := CopyValue(&d, v); err != nil {
		return false
	}

	return true
}

// DeepEqual determines whether the supplied values are deeply equal.
// Values are deeply equal if they have the same type and have the same
// representation when serialized. This will return false if either value
// cannot be represented by the TPM wire format.
func DeepEqual(x, y interface{}) (equal bool) {
	if reflect.TypeOf(x) != reflect.TypeOf(y) {
		return false
	}

	defer func() {
		if err := recover(); err != nil {
			equal = false
		}
	}()

	x2 := MustMarshalToBytes(x)
	y2 := MustMarshalToBytes(y)
	return bytes.Equal(x2, y2)
}
