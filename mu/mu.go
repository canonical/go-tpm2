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
	"strings"

	"golang.org/x/xerrors"
)

var (
	customMuType reflect.Type = reflect.TypeOf((*customMuIface)(nil)).Elem()
	unionType    reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
	nilValueType reflect.Type = reflect.TypeOf(NilUnionValue)
	rawBytesType reflect.Type = reflect.TypeOf(RawBytes(nil))
)

// InvalidSelectorError may be returned as a wrapped error from UnmarshalFromBytes or UnmarshalFromReader when a union type indicates
// that a selector value is invalid.
type InvalidSelectorError struct {
	Selector reflect.Value
}

func (e *InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

type customMuIface interface {
	CustomMarshaller
	CustomUnmarshaller
}

// CustomMarshaller is implemented by types that require custom marshalling behaviour because they are non-standard and not
// directly supported by the marshalling code. This interface should be implemented by types with a value receiver if you want
// to be able to pass it directly by value to MarshalToBytes or MarshalToWriter. Implementations must also implement the
// CustomUnmarshaller interface.
type CustomMarshaller interface {
	Marshal(w io.Writer) error
}

// CustomUnmarshaller is implemented by types that require custom unmarshalling behaviour because they are non-standard and not
// directly supported by the marshalling code. This interface must be implemented by types with a pointer receiver, and types
// must also implement the CustomMarshaller interface.
type CustomUnmarshaller interface {
	Unmarshal(r Reader) error
}

type empty struct{}

// NilUnionValue is a special value, the type of which should be returned from implementations of Union.Select to indicate
// that a union contains no data for a particular selector value.
var NilUnionValue empty

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a size field. The slice must be pre-allocated to
// the correct length by the caller during unmarshalling.
type RawBytes []byte

// Union is implemented by structure types that correspond to TPMU prefixed TPM types.
type Union interface {
	// Select is called by the marshalling code to map the supplied selector to a field. The returned value must be a pointer to
	// the field to be marshalled or unmarshalled. To work correctly during marshalling and unmarshalling, implementations must
	// take a pointer receiver. If no data should be marshalled or unmarshalled, it should return NilUnionValue.
	Select(selector reflect.Value) interface{}
}

type muError struct {
	kind      string
	val       reflect.Value
	container reflect.Value
	err       error
}

func (e *muError) Error() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "cannot process %s type %s", e.kind, e.val.Type())
	if e.container.IsValid() {
		fmt.Fprintf(&b, ", inside container type %s", e.container.Type())
	}
	fmt.Fprintf(&b, ": %v", e.err)
	return b.String()
}

func (e *muError) Unwrap() error {
	return e.err
}

func makeSizedTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "sized", val: val, container: ctx.container, err: err}
}

func makeRawTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "raw", val: val, container: ctx.container, err: err}
}

func makePrimitiveTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "primitive", val: val, container: ctx.container, err: err}
}

func makeListTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "list", val: val, container: ctx.container, err: err}
}

func makeStructTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "struct", val: val, container: ctx.container, err: err}
}

func makeUnionTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "union", val: val, container: ctx.container, err: err}
}

func makeCustomTypeMuError(val reflect.Value, ctx *muContext, err error) error {
	return &muError{kind: "custom", val: val, container: ctx.container, err: err}
}

type structFieldMuError struct {
	val   reflect.Value
	field reflect.StructField
	err   error
}

func (e *structFieldMuError) Error() string {
	return fmt.Sprintf("cannot process field %s from struct type %s: %v", e.field.Name, e.val.Type(), e.err)
}

func (e *structFieldMuError) Unwrap() error {
	return e.err
}

func makeStructFieldMuError(s reflect.Value, index int, err error) error {
	return &structFieldMuError{val: s, field: s.Type().Field(index), err: err}
}

type listElemMuError struct {
	val   reflect.Value
	index int
	err   error
}

func (e *listElemMuError) Error() string {
	return fmt.Sprintf("cannot process element at index %d from list type %s: %v", e.index, e.val.Type(), e.err)
}

func (e *listElemMuError) Unwrap() error {
	return e.err
}

func makeListElemMuError(s reflect.Value, index int, err error) error {
	return &listElemMuError{val: s, index: index, err: err}
}

// MarshalError indicates an error during marshalling and may be returned from MarshalToBytes or MarshalToWriter.
type MarshalError struct {
	Index int // The index of the argument that caused the error
	err   error
}

func (e *MarshalError) Error() string {
	return fmt.Sprintf("cannot marshal argument at index %d: %v", e.Index, e.err)
}

func (e *MarshalError) Unwrap() error {
	return e.err
}

// UnmarshalError indicates an error during unmarshalling and may be returned from UnmarshalFromBytes or UnmarshalFromReader.
type UnmarshalError struct {
	Index int // The index of the argument that caused the error
	err   error
}

func (e *UnmarshalError) Error() string {
	return fmt.Sprintf("cannot unmarshal argument at index %d: %v", e.Index, e.err)
}

func (e *UnmarshalError) Unwrap() error {
	return e.err
}

type muOptions struct {
	selector string
	sized    bool
	raw      bool
}

func parseStructFieldMuOptions(f reflect.StructField) (out muOptions) {
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
	return
}

type muContext struct {
	container reflect.Value
	options   muOptions
}

func (c *muContext) enterStructField(s reflect.Value, i int) (f reflect.Value, exit func()) {
	opts := parseStructFieldMuOptions(s.Type().Field(i))
	origContainer := c.container
	origOptions := c.options
	c.container = s
	c.options = opts

	return s.Field(i), func() {
		c.container = origContainer
		c.options = origOptions
	}
}

func (c *muContext) enterListElem(l reflect.Value, i int) (elem reflect.Value, exit func()) {
	origContainer := c.container
	origOptions := c.options
	c.container = l
	c.options = muOptions{}

	return l.Index(i), func() {
		c.container = origContainer
		c.options = origOptions
	}
}

func (c *muContext) enterUnionElem(u reflect.Value) (elem reflect.Value, exit func(), err error) {
	if !c.container.IsValid() {
		panic(fmt.Sprintf("union type %s is not inside a container", u.Type()))
	}
	if c.options.selector == "" {
		panic(fmt.Sprintf("no selector member for union type %s defined in container type %s", u.Type(), c.container.Type()))
	}

	selectorVal := c.container.FieldByName(c.options.selector)
	if !selectorVal.IsValid() {
		panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field inside container type %s",
			c.options.selector, u.Type(), c.container.Type()))
	}

	p := u.Addr().Interface().(Union).Select(selectorVal)
	switch {
	case p == nil:
		return reflect.Value{}, nil, &InvalidSelectorError{selectorVal}
	case p == NilUnionValue:
		return reflect.Value{}, nil, nil
	}
	elem = reflect.ValueOf(p).Elem()

	origOptions := c.options
	c.options.selector = ""

	return elem, func() {
		c.options = origOptions
	}, nil

}

func (c *muContext) enterSizedType(v reflect.Value) (exit func()) {
	switch {
	case v.Kind() == reflect.Ptr:
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.Uint8:
	default:
		panic(fmt.Sprintf("invalid sized type: %v", v.Type()))
	}

	origOptions := c.options
	c.options.sized = false
	if v.Kind() == reflect.Slice {
		c.options.raw = true
	}

	return func() {
		c.options = origOptions
	}
}

// TPMKind indicates the TPM type class associated with a Go type
type TPMKind int

const (
	TPMKindUnsupported TPMKind = iota
	TPMKindPrimitive
	TPMKindSized
	TPMKindList
	TPMKindStruct
	TPMKindUnion
	TPMKindCustom
	TPMKindRawBytes
	TPMKindRawList
)

func tpmKind(t reflect.Type) TPMKind {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	if reflect.PtrTo(t).Implements(customMuType) {
		return TPMKindCustom
	}

	switch t.Kind() {
	case reflect.Bool, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return TPMKindPrimitive
	case reflect.Slice:
		switch {
		case t == rawBytesType:
			return TPMKindRawBytes
		case t.Elem().Kind() == reflect.Uint8:
			return TPMKindSized
		}
		return TPMKindList
	case reflect.Struct:
		if reflect.PtrTo(t).Implements(unionType) {
			return TPMKindUnion
		}
		return TPMKindStruct
	default:
		return TPMKindUnsupported
	}
}

// DetermineTPMKind returns the TPMKind associated with the supplied go value. It will automatically dereference pointer types.
// Single field structures will be unwrapped and the TPMKind associated with the structure field will be returned.
func DetermineTPMKind(i interface{}) TPMKind {
	t := reflect.TypeOf(i)
	var k TPMKind
	raw := false
	for {
		if t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		k = tpmKind(t)
		if k != TPMKindStruct {
			break
		}
		if t.NumField() != 1 {
			break
		}
		f := t.Field(0)
		opts := parseStructFieldMuOptions(f)
		switch {
		case opts.sized:
			return TPMKindSized
		case opts.raw:
			raw = true
		}
		t = f.Type
	}
	switch {
	case raw && k == TPMKindSized:
		return TPMKindRawBytes
	case raw && k == TPMKindList:
		return TPMKindRawList
	default:
		return k
	}
}

type marshaller struct {
	*muContext
	w      io.Writer
	nbytes int
}

func (m *marshaller) Write(p []byte) (n int, err error) {
	n, err = m.w.Write(p)
	m.nbytes += n
	return
}

func (m *marshaller) marshalSized(v reflect.Value) error {
	exit := m.enterSizedType(v)
	defer exit()

	if v.IsNil() {
		if err := binary.Write(m, binary.BigEndian, uint16(0)); err != nil {
			return xerrors.Errorf("cannot write size of zero sized value: %w", err)
		}
		return nil
	}

	tmpBuf := new(bytes.Buffer)
	sm := &marshaller{muContext: m.muContext, w: tmpBuf}
	if err := sm.marshalValue(v); err != nil {
		return err
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return errors.New("sized value size greater than 2^16-1")
	}
	if err := binary.Write(m, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return xerrors.Errorf("cannot write size of sized value: %w", err)
	}
	if _, err := tmpBuf.WriteTo(m); err != nil {
		return xerrors.Errorf("cannot write marshalled sized value: %w", err)
	}
	return nil
}

func (m *marshaller) marshalRawList(v reflect.Value) error {
	for i := 0; i < v.Len(); i++ {
		elem, exit := m.enterListElem(v, i)
		if err := m.marshalValue(elem); err != nil {
			exit()
			return makeListElemMuError(v, i, err)
		}
		exit()
	}
	return nil
}

func (m *marshaller) marshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		_, err := m.Write(v.Bytes())
		return err
	default:
		return m.marshalRawList(v)
	}
}

func (m *marshaller) marshalPtr(v reflect.Value) error {
	p := v
	if v.IsNil() {
		p = reflect.New(v.Type().Elem())
	}
	return m.marshalValue(p.Elem())
}

func (m *marshaller) marshalPrimitive(v reflect.Value) error {
	return binary.Write(m, binary.BigEndian, v.Interface())
}

func (m *marshaller) marshalList(v reflect.Value) error {
	// int is either 32-bits or 64-bits. We can't compare slice.Len() to math.MaxUint32 when int is 32-bits and it isn't
	// necessary anyway. For the case where int is 64-bits, truncate to uint32 then zero extend it again to int to make
	// sure the original number was preserved.
	if int(uint32(v.Len())) != v.Len() {
		return errors.New("slice length greater than 2^32-1")
	}

	// Marshal length field
	if err := binary.Write(m, binary.BigEndian, uint32(v.Len())); err != nil {
		return xerrors.Errorf("cannot write length of list: %w", err)
	}

	return m.marshalRawList(v)
}

func (m *marshaller) marshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		f, exit := m.enterStructField(v, i)
		if err := m.marshalValue(f); err != nil {
			exit()
			return makeStructFieldMuError(v, i, err)
		}
		exit()
	}

	return nil
}

func (m *marshaller) marshalUnion(v reflect.Value) error {
	// Ignore during marshalling - let the TPM unmarshalling catch it
	elem, exit, _ := m.enterUnionElem(v)
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return m.marshalValue(elem)
}

func (m *marshaller) marshalCustom(v reflect.Value) error {
	return v.Interface().(CustomMarshaller).Marshal(m)
}

func (m *marshaller) marshalValue(v reflect.Value) error {
	switch {
	case m.options.sized:
		if err := m.marshalSized(v); err != nil {
			return makeSizedTypeMuError(v, m.muContext, err)
		}
		return nil
	case m.options.raw:
		if err := m.marshalRaw(v); err != nil {
			return makeRawTypeMuError(v, m.muContext, err)
		}
		return nil
	}

	if v.Kind() == reflect.Ptr {
		return m.marshalPtr(v)
	}

	switch tpmKind(v.Type()) {
	case TPMKindPrimitive:
		if err := m.marshalPrimitive(v); err != nil {
			return makePrimitiveTypeMuError(v, m.muContext, err)
		}
	case TPMKindSized:
		if err := m.marshalSized(v); err != nil {
			return makeSizedTypeMuError(v, m.muContext, err)
		}
	case TPMKindList:
		if err := m.marshalList(v); err != nil {
			return makeListTypeMuError(v, m.muContext, err)
		}
	case TPMKindStruct:
		if err := m.marshalStruct(v); err != nil {
			return makeStructTypeMuError(v, m.muContext, err)
		}
	case TPMKindUnion:
		if err := m.marshalUnion(v); err != nil {
			return makeUnionTypeMuError(v, m.muContext, err)
		}
	case TPMKindCustom:
		if err := m.marshalCustom(v); err != nil {
			return makeCustomTypeMuError(v, m.muContext, err)
		}
	case TPMKindRawBytes:
		if err := m.marshalRaw(v); err != nil {
			return makeRawTypeMuError(v, m.muContext, err)
		}
	default:
		panic(fmt.Sprintf("cannot marshal unsupported type %s", v.Type()))
	}

	return nil
}

// Reader is an interface that groups the io.Reader interface with an additional method to
// obtain the remaining number of bytes that can be read for implementations that support this.
type Reader interface {
	io.Reader
	Len() int
}

type unmarshaller struct {
	*muContext
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

func makeUnmarshaller(ctx *muContext, r io.Reader) (*unmarshaller, error) {
	sz, err := startingSizeOfReader(r)
	if err != nil {
		return nil, err
	}
	return &unmarshaller{muContext: ctx, r: r, sz: sz}, nil
}

func (u *unmarshaller) unmarshalSized(v reflect.Value) error {
	exit := u.enterSizedType(v)
	defer exit()

	var size uint16
	if err := binary.Read(u, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read size of sized value: %w", err)
	}

	switch {
	case size == 0 && !v.IsNil() && v.Kind() == reflect.Ptr:
		return errors.New("sized value is zero sized, but destination value has been pre-allocated")
	case size == 0:
		return nil
	case int(size) > u.Len():
		return errors.New("sized value has a size larger than the remaining bytes")
	case v.Kind() == reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), int(size), int(size)))
	}

	su, err := makeUnmarshaller(u.muContext, io.LimitReader(u, int64(size)))
	if err != nil {
		return xerrors.Errorf("cannot create new reader for sized payload: %w", err)
	}
	return su.unmarshalValue(v)
}

func (u *unmarshaller) unmarshalRawList(v reflect.Value, n int) (reflect.Value, error) {
	for i := 0; i < n; i++ {
		v = reflect.Append(v, reflect.Zero(v.Type().Elem()))
		elem, exit := u.enterListElem(v, i)
		if err := u.unmarshalValue(elem); err != nil {
			exit()
			return reflect.Value{}, makeListElemMuError(v, i, err)
		}
		exit()
	}
	return v, nil
}

func (u *unmarshaller) unmarshalRaw(v reflect.Value) error {
	switch v.Type().Elem().Kind() {
	case reflect.Uint8:
		_, err := io.ReadFull(u, v.Bytes())
		return err
	default:
		_, err := u.unmarshalRawList(v.Slice(0, 0), v.Len())
		return err
	}
}

func (u *unmarshaller) unmarshalPtr(v reflect.Value) error {
	if v.IsNil() {
		v.Set(reflect.New(v.Type().Elem()))
	}
	return u.unmarshalValue(v.Elem())
}

func (u *unmarshaller) unmarshalPrimitive(v reflect.Value) error {
	return binary.Read(u, binary.BigEndian, v.Addr().Interface())
}

func (u *unmarshaller) unmarshalList(v reflect.Value) error {
	// Unmarshal the length
	var length uint32
	if err := binary.Read(u, binary.BigEndian, &length); err != nil {
		return xerrors.Errorf("cannot read length of list: %w", err)
	}

	s, err := u.unmarshalRawList(reflect.MakeSlice(v.Type(), 0, 0), int(length))
	if err != nil {
		return err
	}
	v.Set(s)
	return nil
}

func (u *unmarshaller) unmarshalStruct(v reflect.Value) error {
	for i := 0; i < v.NumField(); i++ {
		elem, exit := u.enterStructField(v, i)
		if err := u.unmarshalValue(elem); err != nil {
			exit()
			return makeStructFieldMuError(v, i, err)
		}
		exit()
	}
	return nil
}

func (u *unmarshaller) unmarshalUnion(v reflect.Value) error {
	elem, exit, err := u.enterUnionElem(v)
	if err != nil {
		return err
	}
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return u.unmarshalValue(elem)
}

func (u *unmarshaller) unmarshalCustom(v reflect.Value) error {
	if v.Kind() != reflect.Ptr {
		v = v.Addr()
	}
	return v.Interface().(CustomUnmarshaller).Unmarshal(u)
}

func (u *unmarshaller) unmarshalValue(v reflect.Value) error {
	switch {
	case u.options.sized:
		if err := u.unmarshalSized(v); err != nil {
			return makeSizedTypeMuError(v, u.muContext, err)
		}
		return nil
	case u.options.raw:
		if err := u.unmarshalRaw(v); err != nil {
			return makeRawTypeMuError(v, u.muContext, err)
		}
		return nil
	}

	if v.Kind() == reflect.Ptr {
		return u.unmarshalPtr(v)
	}

	switch tpmKind(v.Type()) {
	case TPMKindPrimitive:
		if err := u.unmarshalPrimitive(v); err != nil {
			return makePrimitiveTypeMuError(v, u.muContext, err)
		}
	case TPMKindSized:
		if err := u.unmarshalSized(v); err != nil {
			return makeSizedTypeMuError(v, u.muContext, err)
		}
	case TPMKindList:
		if err := u.unmarshalList(v); err != nil {
			return makeListTypeMuError(v, u.muContext, err)
		}
	case TPMKindStruct:
		if err := u.unmarshalStruct(v); err != nil {
			return makeStructTypeMuError(v, u.muContext, err)
		}
	case TPMKindUnion:
		if err := u.unmarshalUnion(v); err != nil {
			return makeUnionTypeMuError(v, u.muContext, err)
		}
	case TPMKindCustom:
		if err := u.unmarshalCustom(v); err != nil {
			return makeCustomTypeMuError(v, u.muContext, err)
		}
	case TPMKindRawBytes:
		if err := u.unmarshalRaw(v); err != nil {
			return makeRawTypeMuError(v, u.muContext, err)
		}
	default:
		panic(fmt.Sprintf("cannot unmarshal unsupported type %s", v.Type()))
	}

	return nil
}

// MarshalToWriter marshals vals to w in the TPM wire format, according to the rules specified in the package description. A nil
// pointer encountered during marshalling causes the zero value for the type to be marshalled, unless the pointer is to a sized
// structure.
//
// The number of bytes written to w are returned. If this function does not complete successfully, it will return an error and
// the number of bytes written.
func MarshalToWriter(w io.Writer, vals ...interface{}) (int, error) {
	var totalBytes int
	for i, val := range vals {
		m := &marshaller{muContext: new(muContext), w: w}
		err := m.marshalValue(reflect.ValueOf(val))
		totalBytes += m.nbytes
		if err != nil {
			return totalBytes, &MarshalError{Index: i, err: err}
		}
	}
	return totalBytes, nil
}

// MarshalToBytes marshals vals to the TPM wire format, according to the rules specified in the package description. A nil pointer
// encountered during marshalling causes the zero value for the type to be marshalled, unless the pointer is to a sized structure.
//
// If successful, this function returns the marshalled data. If this function does not complete successfully, it will return an error.
// In this case, no data will be returned.
func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if _, err := MarshalToWriter(buf, vals...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalFromReader unmarshals data in the TPM wire format from r to vals, according to the rules specified in the package
// description. The values supplied to this function must be pointers to the destination values. Nil pointers encountered during
// unmarshalling will be initialized to point to newly allocated memory, unless the pointer represents a zero-sized structure. New
// slices will always be created - even if the caller pre-allocates them, unless it is a RawBytes type or a struct field with the
// `tpm2:"raw"` tag. In this case, the slice must be preallocated to the expected size.
//
// The number of bytes read from r are returned. If this function does not complete successfully, it will return an error and
// the number of bytes read. In this case, partial results may have been unmarshalled to the supplied destination values.
func UnmarshalFromReader(r io.Reader, vals ...interface{}) (int, error) {
	var totalBytes int
	for i, val := range vals {
		v := reflect.ValueOf(val)
		if v.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", v.Type()))
		}

		if v.IsNil() {
			panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", v.Type()))
		}

		u, err := makeUnmarshaller(new(muContext), r)
		if err != nil {
			return totalBytes, err
		}
		err = u.unmarshalValue(v.Elem())
		totalBytes += u.nbytes
		if err != nil {
			return totalBytes, &UnmarshalError{Index: i, err: err}
		}
	}
	return totalBytes, nil
}

// UnmarshalFromBytes unmarshals data in the TPM wire format from b to vals, according to the rules specified in the package
// description. The values supplied to this function must be pointers to the destination values. Nil pointers encountered during
// unmarshalling will be initialized to point to newly allocated memory, unless the pointer represents a zero-sized structure. New
// slices will always be created - even if the caller pre-allocates them, unless it is a RawBytes type or a struct field with the
// `tpm2:"raw"` tag. In this case, the slice must be preallocated to the expected size.
//
// If successful, this function returns the number of bytes consumed from b. If this function does not complete successfully, it will
// return an error and the number of bytes consumed. In this case, partial results may have been unmarshalled to the supplied
// destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	return UnmarshalFromReader(buf, vals...)
}
