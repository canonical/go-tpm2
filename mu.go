// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

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
	rawBytesType         reflect.Type = reflect.TypeOf(RawBytes(nil))
	unionType            reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
)

type InvalidSelectorError struct {
	Selector reflect.Value
}

func (e InvalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.Selector)
}

// CustomMarshaller is implemented by types that require custom marshalling and unmarshalling behaviour because they are non-standard
// and not directly supported by the marshalling code.
type CustomMarshaller interface {
	Marshal(buf io.Writer) (int, error)
	Unmarshal(buf io.Reader) (int, error)
}

// RawBytes is a special byte slice type which is marshalled and unmarshalled without a size field. The slice must be pre-allocated to
// the correct length by the caller during unmarshalling.
type RawBytes []byte

// Union is implemented by types that implement the TPMU prefixed TPM types.
//
// The Select method is called by the marshalling code with the value of the selector field from the enclosing struct, and the
// implementation should respond with the type that will be marshalled or unmarshalled for the selector value.
type Union interface {
	Select(selector reflect.Value) (reflect.Type, error)
}

func isValidUnionContainer(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	return true
}

func isUnion(t reflect.Type) bool {
	if t.Kind() != reflect.Struct {
		return false
	}
	if !t.Implements(unionType) {
		return false
	}
	if t.NumField() != 1 {
		return false
	}
	if t.Field(0).Type.Kind() != reflect.Interface {
		return false
	}
	return t.Field(0).Type.NumMethod() == 0
}

func isByteSlice(t reflect.Type) bool {
	if t.Kind() != reflect.Slice {
		return false
	}
	return t.Elem().Kind() == reflect.Uint8
}

func hasCustomMarshallerImpl(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Implements(customMarshallerType)

}

type muOptions struct {
	selector string
	sized    bool
	raw      bool
}

func parseFieldOptions(s string) muOptions {
	var opts muOptions
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "selector:"):
			opts.selector = part[9:]
		case part == "sized":
			opts.sized = true
		case part == "raw":
			opts.raw = true
		}
	}
	return opts
}

type muContext struct {
	nbytes    int
	container reflect.Value
	options   muOptions
}

func (c *muContext) enterStructField(s reflect.Value, i int) (exit func()) {
	opts := parseFieldOptions(s.Type().Field(i).Tag.Get("tpm2"))
	origContainer := c.container
	origOptions := c.options
	c.container = s
	c.options = opts
	return func() {
		c.container = origContainer
		c.options = origOptions
	}
}

func (c *muContext) enterContainerElem(e reflect.Value) (exit func()) {
	origContainer := c.container
	origOptions := c.options
	c.container = e
	c.options = muOptions{}
	return func() {
		c.container = origContainer
		c.options = origOptions
	}
}

func (c *muContext) enterSizedStruct() (exit func()) {
	c.options.sized = false
	return func() {
		c.options.sized = true
	}
}

func marshalSized(buf io.Writer, s reflect.Value, ctx *muContext) error {
	switch {
	case s.Kind() != reflect.Ptr:
		panic(fmt.Sprintf("sized field of type %s contained within type %s is not a pointer", s.Type(), ctx.container.Type()))
	case s.Type().Elem().Kind() != reflect.Struct:
		panic(fmt.Sprintf("sized field of type %s contained within type %s is not a pointer to a struct", s.Type(), ctx.container.Type()))
	case s.IsNil():
		if err := binary.Write(buf, binary.BigEndian, uint16(0)); err != nil {
			return xerrors.Errorf("cannot write size of zero sized struct: %w", err)
		}
		ctx.nbytes += binary.Size(uint16(0))
		return nil
	}

	exit := ctx.enterSizedStruct()
	defer exit()

	tmpBuf := new(bytes.Buffer)
	if err := marshalValue(tmpBuf, s, ctx); err != nil {
		return xerrors.Errorf("cannot marshal pointer to struct to temporary buffer: %w", err)
	}
	if tmpBuf.Len() > math.MaxUint16 {
		return errors.New("sized structure length greater than 2^16-1")
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return xerrors.Errorf("cannot write size of struct: %w", err)
	}
	ctx.nbytes += binary.Size(uint16(0))
	n, err := tmpBuf.WriteTo(buf)
	ctx.nbytes += int(n)
	if err != nil {
		return xerrors.Errorf("cannot write marshalled struct: %w", err)
	}
	return nil
}

func marshalPtr(buf io.Writer, ptr reflect.Value, ctx *muContext) error {
	var d reflect.Value
	if ptr.IsNil() {
		d = reflect.Zero(ptr.Type().Elem())
	} else {
		d = ptr.Elem()
	}

	if err := marshalValue(buf, d, ctx); err != nil {
		return xerrors.Errorf("cannot marshal element: %w", err)
	}
	return nil
}

func marshalUnion(buf io.Writer, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		panic(fmt.Sprintf("union type %s is not inside a container", u.Type()))
	}

	if !isValidUnionContainer(ctx.container.Type()) {
		panic(fmt.Sprintf("union type %s is inside a container of type %s which isn't a valid container type", u.Type(),
			ctx.container.Type()))
	}

	if ctx.options.selector == "" {
		panic(fmt.Sprintf("no selector member for union type %s defined in container type %s", u.Type(), ctx.container.Type()))
	}

	selectorVal := ctx.container.FieldByName(ctx.options.selector)
	if !selectorVal.IsValid() {
		panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field inside container type %s",
			ctx.options.selector, u.Type(), ctx.container.Type()))
	}

	// Ignore errors during marshalling as we can produce some confusing errors for really nested elements.
	// In the event of an error, selectedType will be nil, we'll marshal nothing and the TPM's unmarshalling
	// and parameter validation will catch the error when unmarshalling the selector value.
	selectedType, _ := u.Interface().(Union).Select(selectorVal)
	if selectedType == nil {
		return nil
	}

	var d reflect.Value
	f := u.Field(0)
	if f.IsNil() {
		d = reflect.Zero(selectedType)
	} else {
		d = f.Elem()
	}

	if d.Type() != selectedType {
		if !d.Type().ConvertibleTo(selectedType) {
			return xerrors.Errorf("data has incorrect type %s (expected %s)", d.Type(), selectedType)
		}
		d = d.Convert(selectedType)
	}

	exit := ctx.enterContainerElem(u)
	defer exit()
	return marshalValue(buf, d, ctx)
}

func marshalStruct(buf io.Writer, s reflect.Value, ctx *muContext) error {
	if isUnion(s.Type()) {
		if err := marshalUnion(buf, s, ctx); err != nil {
			return xerrors.Errorf("error marshalling union struct: %w", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		exit := ctx.enterStructField(s, i)
		if err := marshalValue(buf, s.Field(i), ctx); err != nil {
			exit()
			return xerrors.Errorf("cannot marshal field %s: %w", s.Type().Field(i).Name, err)
		}
		exit()
	}

	return nil
}

func marshalSlice(buf io.Writer, slice reflect.Value, ctx *muContext) error {
	if isByteSlice(slice.Type()) {
		// Shortcut for byte slices
		if slice.Type() != rawBytesType && !ctx.options.raw {
			// Sized buffer
			if slice.Len() > math.MaxUint16 {
				return errors.New("sized buffer length greater than 2^16-1")
			}

			if err := binary.Write(buf, binary.BigEndian, uint16(slice.Len())); err != nil {
				return xerrors.Errorf("cannot write size of sized buffer: %w", err)
			}
			ctx.nbytes += binary.Size(uint16(0))
		}
		n, err := buf.Write(slice.Bytes())
		ctx.nbytes += n
		if err != nil {
			return xerrors.Errorf("cannot write byte slice contents: %w", err)
		}
		return nil
	}

	// int is either 32-bits or 64-bits. We can't compare slice.Len() to math.MaxUint32 when int is 32-bits and it isn't
	// necessary anyway. For the case where int is 64-bits, truncate to uint32 then zero extend it again to int to make
	// sure the original number was preserved.
	if int(uint32(slice.Len())) != slice.Len() {
		return errors.New("slice length greater than 2^32-1")
	}

	if !ctx.options.raw {
		// Marshal length field
		if err := binary.Write(buf, binary.BigEndian, uint32(slice.Len())); err != nil {
			return xerrors.Errorf("cannot write length of list: %w", err)
		}
		ctx.nbytes += binary.Size(uint32(0))
	}

	for i := 0; i < slice.Len(); i++ {
		exit := ctx.enterContainerElem(slice)
		if err := marshalValue(buf, slice.Index(i), ctx); err != nil {
			exit()
			return xerrors.Errorf("cannot marshal value at index %d: %w", i, err)
		}
		exit()
	}
	return nil
}

func marshalValue(buf io.Writer, val reflect.Value, ctx *muContext) error {
	if ctx.options.sized {
		if err := marshalSized(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot marshal sized type %s: %w", val.Type(), err)
		}
		return nil
	}

	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		case val.IsNil():
			val = reflect.New(val.Type().Elem())
		}
		n, err := val.Interface().(CustomMarshaller).Marshal(buf)
		ctx.nbytes += n
		if err != nil {
			return xerrors.Errorf("cannot marshal type %s with custom marshaller: %w", origVal.Type(), err)
		}
		return nil
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := marshalPtr(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot marshal pointer type %s: %w", val.Type(), err)
		}
	case reflect.Struct:
		if err := marshalStruct(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot marshal struct type %s: %w", val.Type(), err)
		}
	case reflect.Slice:
		if err := marshalSlice(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot marshal slice type %s: %w", val.Type(), err)
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
		panic(fmt.Sprintf("cannot marshal type %s: unsupported kind %s", val.Type(), val.Kind()))
	default:
		if err := binary.Write(buf, binary.BigEndian, val.Interface()); err != nil {
			return xerrors.Errorf("cannot marshal type %s: write to buffer failed: %w", val.Type(), err)
		}
		ctx.nbytes += binary.Size(val.Interface())
	}
	return nil
}

func unmarshalSized(buf io.Reader, s reflect.Value, ctx *muContext) error {
	switch {
	case s.Kind() != reflect.Ptr:
		panic(fmt.Sprintf("sized field of type %s contained within type %s is not a pointer", s.Type(), ctx.container.Type()))
	case s.Type().Elem().Kind() != reflect.Struct:
		panic(fmt.Sprintf("sized field of type %s contained within type %s is not a pointer to a struct", s.Type(), ctx.container.Type()))
	}

	var size uint16
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read size of struct: %w", err)
	}
	ctx.nbytes += binary.Size(uint16(0))
	switch {
	case size == 0 && !s.IsNil():
		return errors.New("struct is zero sized, but destination struct has been pre-allocated")
	case size == 0:
		return nil
	}

	exit := ctx.enterSizedStruct()
	defer exit()

	lr := io.LimitReader(buf, int64(size))
	if err := unmarshalValue(lr, s, ctx); err != nil {
		return xerrors.Errorf("cannot unmarshal pointer to struct: %w", err)
	}
	return nil
}

func unmarshalPtr(buf io.Reader, ptr reflect.Value, ctx *muContext) error {
	if ptr.IsNil() {
		ptr.Set(reflect.New(ptr.Type().Elem()))
	}

	if err := unmarshalValue(buf, ptr.Elem(), ctx); err != nil {
		return xerrors.Errorf("cannot unmarshal element: %w", err)
	}
	return nil
}

func unmarshalUnion(buf io.Reader, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		panic(fmt.Sprintf("union type %s is not inside a container", u.Type()))
	}

	if !isValidUnionContainer(ctx.container.Type()) {
		panic(fmt.Sprintf("union type %s is inside a container of type %s which isn't a valid container type", u.Type(),
			ctx.container.Type()))
	}

	if ctx.options.selector == "" {
		panic(fmt.Sprintf("no selector member for union type %s defined in container type %s", u.Type(), ctx.container.Type()))
	}

	selectorVal := ctx.container.FieldByName(ctx.options.selector)
	if !selectorVal.IsValid() {
		panic(fmt.Sprintf("selector name %s for union type %s does not reference a valid field inside container type %s",
			ctx.options.selector, u.Type(), ctx.container.Type()))
	}

	selectedType, err := u.Interface().(Union).Select(selectorVal)
	if err != nil {
		return xerrors.Errorf("cannot select union data type: %w", err)
	}
	if selectedType == nil {
		return nil
	}

	var d reflect.Value
	f := u.Field(0)
	if f.IsNil() {
		d = reflect.New(selectedType).Elem()
	} else {
		d = f.Elem()
	}

	exit := ctx.enterContainerElem(u)
	defer exit()

	if err := unmarshalValue(buf, d, ctx); err != nil {
		return xerrors.Errorf("cannot unmarshal data value: %w", err)
	}

	if f.IsNil() {
		f.Set(d)
	}

	return nil
}

func unmarshalStruct(buf io.Reader, s reflect.Value, ctx *muContext) error {
	if isUnion(s.Type()) {
		if err := unmarshalUnion(buf, s, ctx); err != nil {
			return xerrors.Errorf("error unmarshalling union struct: %w", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		exit := ctx.enterStructField(s, i)
		if err := unmarshalValue(buf, s.Field(i), ctx); err != nil {
			exit()
			return xerrors.Errorf("cannot unmarshal field %s: %w", s.Type().Field(i).Name, err)
		}
		exit()
	}
	return nil
}

func unmarshalSlice(buf io.Reader, slice reflect.Value, ctx *muContext) error {
	if isByteSlice(slice.Type()) {
		// Shortcut for byte slice
		switch {
		case (slice.Type() == rawBytesType || ctx.options.raw) && slice.IsNil():
			return errors.New("nil raw byte slice")
		case slice.Type() == rawBytesType || ctx.options.raw:
			// No size
		default:
			// Sized buffer
			var size uint16
			if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
				return xerrors.Errorf("cannot read size of sized buffer: %w", err)
			}
			ctx.nbytes += binary.Size(uint16(0))
			slice.Set(reflect.MakeSlice(slice.Type(), int(size), int(size)))
		}
		n, err := io.ReadFull(buf, slice.Bytes())
		ctx.nbytes += n
		if err != nil {
			return xerrors.Errorf("cannot read byte slice directly from input buffer: %w", err)
		}
		return nil
	}

	// Unmarshal the length
	switch {
	case ctx.options.raw && slice.IsNil():
		return errors.New("nil raw slice")
	case ctx.options.raw:
		// No length
	default:
		var length uint32
		if err := binary.Read(buf, binary.BigEndian, &length); err != nil {
			return xerrors.Errorf("cannot read length of list: %w", err)
		}
		ctx.nbytes += binary.Size(uint32(0))
		slice.Set(reflect.MakeSlice(slice.Type(), int(length), int(length)))
	}

	for i := 0; i < slice.Len(); i++ {
		exit := ctx.enterContainerElem(slice)
		if err := unmarshalValue(buf, slice.Index(i), ctx); err != nil {
			exit()
			return xerrors.Errorf("cannot unmarshal value at index %d: %w", i, err)
		}
		exit()
	}
	return nil
}

func unmarshalValue(buf io.Reader, val reflect.Value, ctx *muContext) error {
	if ctx.options.sized {
		if err := unmarshalSized(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot unmarshal sized type %s: %w", val.Type(), err)
		}
		return nil
	}

	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		default:
			if val.IsNil() {
				val.Set(reflect.New(val.Type().Elem()))
			}
		}
		n, err := val.Interface().(CustomMarshaller).Unmarshal(buf)
		ctx.nbytes += n
		if err != nil {
			return xerrors.Errorf("cannot unmarshal type %s with custom marshaller: %w", origVal.Type(), err)
		}
		return nil
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := unmarshalPtr(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot unmarshal pointer type %s: %w", val.Type(), err)
		}
	case reflect.Struct:
		if err := unmarshalStruct(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot unmarshal struct type %s: %w", val.Type(), err)
		}
	case reflect.Slice:
		if err := unmarshalSlice(buf, val, ctx); err != nil {
			return xerrors.Errorf("cannot unmarshal slice type %s: %w", val.Type(), err)
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
		panic(fmt.Sprintf("cannot unmarshal type %s: unsupported kind %s", val.Type(), val.Kind()))
	default:
		if err := binary.Read(buf, binary.BigEndian, val.Addr().Interface()); err != nil {
			return xerrors.Errorf("cannot unmarshal type %s: read from buffer failed: %w", val.Type(), err)
		}
		ctx.nbytes += binary.Size(val.Interface())
	}
	return nil
}

// MarshalToWriter marshals vals to buf in the TPM wire format, according to the rules specified in "Parameter marshalling and
// unmarshalling". A nil pointer encountered during marshalling causes the zero value for the type to be marshalled, unless the
// pointer is to a sized structure.
//
// The number of bytes written to buf are returned. If this function does not complete successfully, it will return an error and
// the number of bytes written.
func MarshalToWriter(buf io.Writer, vals ...interface{}) (int, error) {
	var totalBytes int
	for _, val := range vals {
		ctx := new(muContext)
		if err := marshalValue(buf, reflect.ValueOf(val), ctx); err != nil {
			return totalBytes + ctx.nbytes, err
		}
		totalBytes += ctx.nbytes
	}
	return totalBytes, nil
}

// MarshalToBytes marshals vals to the TPM wire format, according to the rules specified in "Parameter marshalling and unmarshalling".
// A nil pointer encountered during marshalling causes the zero value for the type to be marshalled, unless the pointer is to a sized
// structure.
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

// UnmarshalFromReader unmarshals data in the TPM wire format from buf to vals, according to the rules specified in "Parameter
// marshalling and unmarshalling". The values supplied to this function must be pointers to the destination values. Nil pointer
// fields encountered during unmarshalling will result in memory being allocated for those values, unless the pointer represents a
// zero-sized sized struct. New slices will always be created - even if the caller pre-allocates them, unless it is a RawBytes type
// or a field with the `tpm2:"raw"` tag.
//
// The number of bytes read from buf are returned. If this function does not complete successfully, it will return an error and
// the number of bytes read. In this case, partial results may have been unmarshalled to the supplied destination values.
func UnmarshalFromReader(buf io.Reader, vals ...interface{}) (int, error) {
	var totalBytes int
	for _, val := range vals {
		v := reflect.ValueOf(val)
		if v.Kind() != reflect.Ptr {
			panic(fmt.Sprintf("cannot unmarshal to non-pointer type %s", v.Type()))
		}

		if v.IsNil() {
			panic(fmt.Sprintf("cannot unmarshal to nil pointer of type %s", v.Type()))
		}

		ctx := new(muContext)
		if err := unmarshalValue(buf, v.Elem(), ctx); err != nil {
			return totalBytes + ctx.nbytes, err
		}
		totalBytes += ctx.nbytes
	}
	return totalBytes, nil
}

// UnmarshalFromBytes unmarshals data in the TPM wire format from b to vals, according to the rules specified in "Parameter
// marshalling and unmarshalling". The values supplied to this function must be pointers to the destination values. Nil pointer
// fields encountered during unmarshalling will result in memory being allocated for those values, unless the pointer represents a
// zero-sized sized struct. New slices will always be created - even if the caller pre-allocates them, unless it is a RawBytes type
// or a field with the `tpm2:"raw"` tag.
//
// If successful, this function returns the number of bytes consumed from b. If this function does not complete successfully, it will
// return an error and the number of bytes consumed. In this case, partial results may have been unmarshalled to the supplied
// destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	return UnmarshalFromReader(buf, vals...)
}
