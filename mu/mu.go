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
	"strings"

	"golang.org/x/xerrors"
)

var (
	customMarshallerType reflect.Type = reflect.TypeOf((*CustomMarshaller)(nil)).Elem()
	unionType            reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
	nilValueType         reflect.Type = reflect.TypeOf(NilUnionValue)
	rawBytesType         reflect.Type = reflect.TypeOf(RawBytes(nil))
)

// InvalidSelectorError may be returned as a wrapped error from UnmarshalFromBytes or UnmarshalFromReader when a union type indicates
// that a selector value is invalid.
type InvalidSelectorError struct {
	Selector reflect.Value
}

func (e *InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

// CustomMarshaller is implemented by types that require custom marshalling and unmarshalling behaviour because they are non-standard
// and not directly supported by the marshalling code.
type CustomMarshaller interface {
	Marshal(buf io.Writer) error
	Unmarshal(buf io.Reader) error
}

type empty struct{}

// NilUnionValue is a special value, the type of which should be returned from implementations of Union.Select to indicate
// that a union contains no data for a particular selector value.
var NilUnionValue empty

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a size field. The slice must be pre-allocated to
// the correct length by the caller during unmarshalling.
type RawBytes []byte

// Union is implemented by types that implement the TPMU prefixed TPM types. Implementations of this should be structures with
// a single member of the empty interface type.
type Union interface {
	// Select is called by the marshalling code with the value of the selector field from the enclosing struct. The implementation
	// should respond with the type that will be marshalled or unmarshalled for the selector value. If no data should be marshalled
	// or unmarshalled, it should respond with the type of NilUnionValue.
	Select(selector reflect.Value) reflect.Type
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

func (c *muContext) enterUnionElem(u reflect.Value, unmarshal bool) (elem reflect.Value, exit func(), err error) {
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

	selectedType := u.Interface().(Union).Select(selectorVal)
	switch {
	case selectedType == nil && unmarshal:
		return reflect.Value{}, nil, &InvalidSelectorError{selectorVal}
	case selectedType == nil || selectedType == nilValueType:
		return reflect.Value{}, nil, nil
	}

	var d reflect.Value
	f := u.Field(0)
	switch {
	case f.IsNil():
		d = reflect.New(selectedType).Elem()
	default:
		d = f.Elem()
	}

	if d.Type() != selectedType {
		if !d.Type().ConvertibleTo(selectedType) {
			return reflect.Value{}, nil, xerrors.Errorf("data has incorrect type %s (expected %s)", d.Type(), selectedType)
		}
		d = d.Convert(selectedType)
	}

	origOptions := c.options
	c.options.selector = ""

	return d, func() {
		c.options = origOptions

		if f.IsNil() && unmarshal {
			f.Set(d)
		}
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

	if reflect.PtrTo(t).Implements(customMarshallerType) {
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
		if t.Implements(unionType) && t.NumField() == 1 && t.Field(0).Type.Kind() == reflect.Interface && t.Field(0).Type.NumMethod() == 0 {
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

type marshalWriter struct {
	w      io.Writer
	nbytes int
}

func (w *marshalWriter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	w.nbytes += n
	return
}

func marshalSized(w io.Writer, val reflect.Value, ctx *muContext) error {
	exit := ctx.enterSizedType(val)
	defer exit()

	if val.IsNil() {
		if err := binary.Write(w, binary.BigEndian, uint16(0)); err != nil {
			return xerrors.Errorf("cannot write size of zero sized value: %w", err)
		}
		return nil
	}

	tmpBuf := new(bytes.Buffer)
	if err := marshalValue(tmpBuf, val, ctx); err != nil {
		return err
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return errors.New("sized value size greater than 2^16-1")
	}
	if err := binary.Write(w, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return xerrors.Errorf("cannot write size of sized value: %w", err)
	}
	if _, err := tmpBuf.WriteTo(w); err != nil {
		return xerrors.Errorf("cannot write marshalled sized value: %w", err)
	}
	return nil
}

func marshalRawList(w io.Writer, slice reflect.Value, ctx *muContext) error {
	for i := 0; i < slice.Len(); i++ {
		elem, exit := ctx.enterListElem(slice, i)
		if err := marshalValue(w, elem, ctx); err != nil {
			exit()
			return makeListElemMuError(slice, i, err)
		}
		exit()
	}
	return nil
}

func marshalRaw(w io.Writer, slice reflect.Value, ctx *muContext) error {
	switch slice.Type().Elem().Kind() {
	case reflect.Uint8:
		_, err := w.Write(slice.Bytes())
		return err
	default:
		return marshalRawList(w, slice, ctx)
	}
}

func marshalPtr(w io.Writer, ptr reflect.Value, ctx *muContext) error {
	p := ptr
	if ptr.IsNil() {
		p = reflect.New(ptr.Type().Elem())
	}
	return marshalValue(w, p.Elem(), ctx)
}

func marshalPrimitive(w io.Writer, val reflect.Value, ctx *muContext) error {
	return binary.Write(w, binary.BigEndian, val.Interface())
}

func marshalList(w io.Writer, slice reflect.Value, ctx *muContext) error {
	// int is either 32-bits or 64-bits. We can't compare slice.Len() to math.MaxUint32 when int is 32-bits and it isn't
	// necessary anyway. For the case where int is 64-bits, truncate to uint32 then zero extend it again to int to make
	// sure the original number was preserved.
	if int(uint32(slice.Len())) != slice.Len() {
		return errors.New("slice length greater than 2^32-1")
	}

	// Marshal length field
	if err := binary.Write(w, binary.BigEndian, uint32(slice.Len())); err != nil {
		return xerrors.Errorf("cannot write length of list: %w", err)
	}

	return marshalRawList(w, slice, ctx)
}

func marshalStruct(w io.Writer, s reflect.Value, ctx *muContext) error {
	for i := 0; i < s.NumField(); i++ {
		f, exit := ctx.enterStructField(s, i)
		if err := marshalValue(w, f, ctx); err != nil {
			exit()
			return makeStructFieldMuError(s, i, err)
		}
		exit()
	}

	return nil
}

func marshalUnion(w io.Writer, u reflect.Value, ctx *muContext) error {
	elem, exit, err := ctx.enterUnionElem(u, false)
	if err != nil {
		return err
	}
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return marshalValue(w, elem, ctx)
}

func marshalCustom(w io.Writer, val reflect.Value, ctx *muContext) error {
	if val.Kind() != reflect.Ptr {
		val = val.Addr()
	}
	return val.Interface().(CustomMarshaller).Marshal(w)
}

func marshalValue(w io.Writer, val reflect.Value, ctx *muContext) error {
	switch {
	case ctx.options.sized:
		if err := marshalSized(w, val, ctx); err != nil {
			return makeSizedTypeMuError(val, ctx, err)
		}
		return nil
	case ctx.options.raw:
		if err := marshalRaw(w, val, ctx); err != nil {
			return makeRawTypeMuError(val, ctx, err)
		}
		return nil
	}

	if val.Kind() == reflect.Ptr {
		return marshalPtr(w, val, ctx)
	}

	switch tpmKind(val.Type()) {
	case TPMKindPrimitive:
		if err := marshalPrimitive(w, val, ctx); err != nil {
			return makePrimitiveTypeMuError(val, ctx, err)
		}
	case TPMKindSized:
		if err := marshalSized(w, val, ctx); err != nil {
			return makeSizedTypeMuError(val, ctx, err)
		}
	case TPMKindList:
		if err := marshalList(w, val, ctx); err != nil {
			return makeListTypeMuError(val, ctx, err)
		}
	case TPMKindStruct:
		if err := marshalStruct(w, val, ctx); err != nil {
			return makeStructTypeMuError(val, ctx, err)
		}
	case TPMKindUnion:
		if err := marshalUnion(w, val, ctx); err != nil {
			return err
		}
	case TPMKindCustom:
		if err := marshalCustom(w, val, ctx); err != nil {
			return makeCustomTypeMuError(val, ctx, err)
		}
	case TPMKindRawBytes:
		if err := marshalRaw(w, val, ctx); err != nil {
			return makeRawTypeMuError(val, ctx, err)
		}
	default:
		panic(fmt.Sprintf("cannot marshal unsupported type %s", val.Type()))
	}

	return nil
}

type unmarshalReader struct {
	r      io.Reader
	nbytes int
}

func (r *unmarshalReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.nbytes += n
	return
}

func unmarshalSized(r io.Reader, val reflect.Value, ctx *muContext) error {
	exit := ctx.enterSizedType(val)
	defer exit()

	var size uint16
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read size of sized value: %w", err)
	}

	switch {
	case size == 0 && !val.IsNil() && val.Kind() == reflect.Ptr:
		return errors.New("sized value is zero sized, but destination value has been pre-allocated")
	case size == 0:
		return nil
	case val.Kind() == reflect.Slice:
		val.Set(reflect.MakeSlice(val.Type(), int(size), int(size)))
	}

	lr := io.LimitReader(r, int64(size))
	return unmarshalValue(lr, val, ctx)
}

func unmarshalRawList(r io.Reader, slice reflect.Value, ctx *muContext) error {
	if slice.IsNil() {
		return errors.New("nil raw slice")
	}

	for i := 0; i < slice.Len(); i++ {
		elem, exit := ctx.enterListElem(slice, i)
		if err := unmarshalValue(r, elem, ctx); err != nil {
			exit()
			return makeListElemMuError(slice, i, err)
		}
		exit()
	}
	return nil
}

func unmarshalRaw(r io.Reader, slice reflect.Value, ctx *muContext) error {
	switch slice.Type().Elem().Kind() {
	case reflect.Uint8:
		_, err := io.ReadFull(r, slice.Bytes())
		return err
	default:
		return unmarshalRawList(r, slice, ctx)
	}
}

func unmarshalPtr(r io.Reader, ptr reflect.Value, ctx *muContext) error {
	if ptr.IsNil() {
		ptr.Set(reflect.New(ptr.Type().Elem()))
	}
	return unmarshalValue(r, ptr.Elem(), ctx)
}

func unmarshalPrimitive(r io.Reader, val reflect.Value, ctx *muContext) error {
	return binary.Read(r, binary.BigEndian, val.Addr().Interface())
}

func unmarshalList(r io.Reader, slice reflect.Value, ctx *muContext) error {
	// Unmarshal the length
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return xerrors.Errorf("cannot read length of list: %w", err)
	}
	slice.Set(reflect.MakeSlice(slice.Type(), int(length), int(length)))

	return unmarshalRawList(r, slice, ctx)
}

func unmarshalStruct(r io.Reader, s reflect.Value, ctx *muContext) error {
	for i := 0; i < s.NumField(); i++ {
		elem, exit := ctx.enterStructField(s, i)
		if err := unmarshalValue(r, elem, ctx); err != nil {
			exit()
			return makeStructFieldMuError(s, i, err)
		}
		exit()
	}
	return nil
}

func unmarshalUnion(r io.Reader, u reflect.Value, ctx *muContext) error {
	elem, exit, err := ctx.enterUnionElem(u, true)
	if err != nil {
		return err
	}
	if !elem.IsValid() {
		return nil
	}
	defer exit()
	return unmarshalValue(r, elem, ctx)
}

func unmarshalCustom(r io.Reader, val reflect.Value, ctx *muContext) error {
	if val.Kind() != reflect.Ptr {
		val = val.Addr()
	}
	return val.Interface().(CustomMarshaller).Unmarshal(r)
}

func unmarshalValue(r io.Reader, val reflect.Value, ctx *muContext) error {
	switch {
	case ctx.options.sized:
		if err := unmarshalSized(r, val, ctx); err != nil {
			return makeSizedTypeMuError(val, ctx, err)
		}
		return nil
	case ctx.options.raw:
		if err := unmarshalRaw(r, val, ctx); err != nil {
			return makeRawTypeMuError(val, ctx, err)
		}
		return nil
	}

	if val.Kind() == reflect.Ptr {
		return unmarshalPtr(r, val, ctx)
	}

	switch tpmKind(val.Type()) {
	case TPMKindPrimitive:
		if err := unmarshalPrimitive(r, val, ctx); err != nil {
			return makePrimitiveTypeMuError(val, ctx, err)
		}
	case TPMKindSized:
		if err := unmarshalSized(r, val, ctx); err != nil {
			return makeSizedTypeMuError(val, ctx, err)
		}
	case TPMKindList:
		if err := unmarshalList(r, val, ctx); err != nil {
			return makeListTypeMuError(val, ctx, err)
		}
	case TPMKindStruct:
		if err := unmarshalStruct(r, val, ctx); err != nil {
			return makeStructTypeMuError(val, ctx, err)
		}
	case TPMKindUnion:
		if err := unmarshalUnion(r, val, ctx); err != nil {
			return err
		}
	case TPMKindCustom:
		if err := unmarshalCustom(r, val, ctx); err != nil {
			return makeCustomTypeMuError(val, ctx, err)
		}
	case TPMKindRawBytes:
		if err := unmarshalRaw(r, val, ctx); err != nil {
			return makeRawTypeMuError(val, ctx, err)
		}
	default:
		panic(fmt.Sprintf("cannot marshal unsupported type %s", val.Type()))
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
		ctx := new(muContext)
		mw := &marshalWriter{w: w}
		err := marshalValue(mw, reflect.ValueOf(val), ctx)
		totalBytes += mw.nbytes
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

		ctx := new(muContext)
		ur := &unmarshalReader{r: r}
		err := unmarshalValue(ur, v.Elem(), ctx)
		totalBytes += ur.nbytes
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
