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
	"reflect"
	"strings"
)

var (
	customMarshallerType reflect.Type = reflect.TypeOf((*CustomMarshaller)(nil)).Elem()
	rawBytesType         reflect.Type = reflect.TypeOf(RawBytes(nil))
	unionType            reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
)

type invalidSelectorError struct {
	selector interface{}
}

func (e invalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.selector)
}

// CustomMarshaller is implemented by types that require custom marshalling and unmarshalling behaviour because they are non-standard
// and not directly supported by the marshalling code.
type CustomMarshaller interface {
	Marshal(buf io.Writer) error
	Unmarshal(buf io.Reader) error
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
	depth     int
	container reflect.Value
	options   muOptions
}

func beginStructFieldCtx(ctx *muContext, s reflect.Value, i int) *muContext {
	opts := parseFieldOptions(s.Type().Field(i).Tag.Get("tpm2"))
	return &muContext{depth: ctx.depth, container: s, options: opts}
}

func beginUnionDataCtx(ctx *muContext, u reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: u}
}

func beginSliceElemCtx(ctx *muContext, s reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: s}
}

func beginPtrElemCtx(ctx *muContext, p reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: ctx.container, options: ctx.options}
}

func beginSizedStructCtx(ctx *muContext) *muContext {
	out := &muContext{depth: ctx.depth, container: ctx.container, options: ctx.options}
	out.options.sized = false
	return out
}

func marshalSized(buf io.Writer, s reflect.Value, ctx *muContext) error {
	switch {
	case s.Kind() != reflect.Ptr:
		return errors.New("not a pointer")
	case s.Type().Elem().Kind() != reflect.Struct:
		return errors.New("not a pointer to a struct")
	case s.IsNil():
		if err := binary.Write(buf, binary.BigEndian, uint16(0)); err != nil {
			return &wrapError{fmt.Sprintf("cannot write size of zero sized struct: %v", err), err}
		}
		return nil
	}

	tmpBuf := new(bytes.Buffer)
	if err := marshalPtr(tmpBuf, s, beginSizedStructCtx(ctx)); err != nil {
		return &wrapError{fmt.Sprintf("cannot marshal pointer to struct to temporary buffer: %v", err), err}
	}
	if err := binary.Write(buf, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return &wrapError{fmt.Sprintf("cannot write size of struct: %v", err), err}
	}
	if _, err := tmpBuf.WriteTo(buf); err != nil {
		return &wrapError{fmt.Sprintf("cannot write marshalled struct: %v", err), err}
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

	if err := marshalValue(buf, d, beginPtrElemCtx(ctx, ptr)); err != nil {
		return &wrapError{fmt.Sprintf("cannot marshal element: %v", err), err}
	}
	return nil
}

func marshalUnion(buf io.Writer, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		return errors.New("not inside a container")
	}

	if !isValidUnionContainer(ctx.container.Type()) {
		return errors.New("not inside a valid union container")
	}

	if ctx.options.selector == "" {
		return errors.New("no selector member defined in container")
	}

	selectorVal := ctx.container.FieldByName(ctx.options.selector)
	if !selectorVal.IsValid() {
		return fmt.Errorf("invalid selector member name %s", ctx.options.selector)
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
			return fmt.Errorf("data has incorrect type %s (expected %s)", d.Type(), selectedType)
		}
		d = d.Convert(selectedType)
	}

	return marshalValue(buf, d, beginUnionDataCtx(ctx, u))
}

func marshalStruct(buf io.Writer, s reflect.Value, ctx *muContext) error {
	if isUnion(s.Type()) {
		if err := marshalUnion(buf, s, ctx); err != nil {
			return &wrapError{fmt.Sprintf("error marshalling union struct: %v", err), err}
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := marshalValue(buf, s.Field(i), beginStructFieldCtx(ctx, s, i)); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal field %s: %v", s.Type().Field(i).Name, err), err}
		}
	}

	return nil
}

func marshalSlice(buf io.Writer, slice reflect.Value, ctx *muContext) error {
	if isByteSlice(slice.Type()) {
		// Shortcut for byte slices
		if slice.Type() != rawBytesType && !ctx.options.raw {
			// Sized buffer
			if err := binary.Write(buf, binary.BigEndian, uint16(slice.Len())); err != nil {
				return &wrapError{fmt.Sprintf("cannot write size of sized buffer: %v", err), err}
			}
		}
		_, err := buf.Write(slice.Bytes())
		if err != nil {
			return &wrapError{fmt.Sprintf("cannot write byte slice contents: %v", err), err}
		}
		return nil
	}

	if !ctx.options.raw {
		// Marshal length field
		if err := binary.Write(buf, binary.BigEndian, uint32(slice.Len())); err != nil {
			return &wrapError{fmt.Sprintf("cannot write length of list: %v", err), err}
		}
	}

	for i := 0; i < slice.Len(); i++ {
		if err := marshalValue(buf, slice.Index(i), beginSliceElemCtx(ctx, slice)); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal value at index %d: %v", i, err), err}
		}
	}
	return nil
}

func marshalValue(buf io.Writer, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr && !val.CanAddr():
			return fmt.Errorf("cannot marshal non-addressable non-pointer type %s with custom marshaller", val.Type())
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		case val.IsNil():
			return fmt.Errorf("cannot marshal nil pointer type %s with custom marshaller", val.Type())
		}
		if err := val.Interface().(CustomMarshaller).Marshal(buf); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal type %s with custom marshaller: %v", origVal.Type(), err), err}
		}
		return nil
	}

	if ctx == nil {
		ctx = new(muContext)
	} else {
		ctx.depth++
	}

	if ctx.options.sized {
		if err := marshalSized(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal sized type %s: %v", val.Type(), err), err}
		}
		return nil
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := marshalPtr(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal pointer type %s: %v", val.Type(), err), err}
		}
	case reflect.Struct:
		if err := marshalStruct(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal struct type %s: %v", val.Type(), err), err}
		}
	case reflect.Slice:
		if err := marshalSlice(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal slice type %s: %v", val.Type(), err), err}
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
		return fmt.Errorf("cannot marshal type %s: unsupported kind %s", val.Type(), val.Kind())
	default:
		if err := binary.Write(buf, binary.BigEndian, val.Interface()); err != nil {
			return &wrapError{fmt.Sprintf("cannot marshal type %s: write to buffer failed: %v", val.Type(), err), err}
		}
	}
	return nil
}

func unmarshalSized(buf io.Reader, s reflect.Value, ctx *muContext) error {
	switch {
	case s.Kind() != reflect.Ptr:
		return errors.New("not a pointer")
	case s.Type().Elem().Kind() != reflect.Struct:
		return errors.New("not a pointer to a struct")
	}

	var size uint16
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return &wrapError{fmt.Sprintf("cannot read size of struct: %v", err), err}
	}
	switch {
	case size == 0 && !s.IsNil():
		return errors.New("struct is zero sized, but destination struct has been pre-allocated")
	case size == 0:
		return nil
	}

	lr := io.LimitReader(buf, int64(size))
	if err := unmarshalPtr(lr, s, beginSizedStructCtx(ctx)); err != nil {
		return &wrapError{fmt.Sprintf("cannot unmarshal pointer to struct: %v", err), err}
	}
	return nil
}

func unmarshalPtr(buf io.Reader, ptr reflect.Value, ctx *muContext) error {
	switch {
	case ptr.IsNil() && !ptr.CanSet():
		return errors.New("cannot set pointer")
	case ptr.IsNil():
		ptr.Set(reflect.New(ptr.Type().Elem()))
	}

	if err := unmarshalValue(buf, ptr.Elem(), beginPtrElemCtx(ctx, ptr)); err != nil {
		return &wrapError{fmt.Sprintf("cannot unmarshal element: %v", err), err}
	}
	return nil
}

func unmarshalUnion(buf io.Reader, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		return errors.New("not inside a container")
	}

	if !isValidUnionContainer(ctx.container.Type()) {
		return errors.New("not inside a valid union container")
	}

	if ctx.options.selector == "" {
		return errors.New("no selector member defined in container")
	}

	selectorVal := ctx.container.FieldByName(ctx.options.selector)
	if !selectorVal.IsValid() {
		return fmt.Errorf("invalid selector member name %s", ctx.options.selector)
	}

	selectedType, err := u.Interface().(Union).Select(selectorVal)
	if err != nil {
		return &wrapError{fmt.Sprintf("cannot select union data type: %v", err), err}
	}
	if selectedType == nil {
		return nil
	}

	var d reflect.Value
	f := u.Field(0)
	if f.IsNil() {
		if !f.CanSet() {
			return errors.New("cannot set data")
		}
		d = reflect.New(selectedType).Elem()
	} else {
		d = f.Elem()
	}

	if err := unmarshalValue(buf, d, beginUnionDataCtx(ctx, u)); err != nil {
		return &wrapError{fmt.Sprintf("cannot unmarshal data value: %v", err), err}
	}

	if f.IsNil() {
		f.Set(d)
	}

	return nil
}

func unmarshalStruct(buf io.Reader, s reflect.Value, ctx *muContext) error {
	if isUnion(s.Type()) {
		if err := unmarshalUnion(buf, s, ctx); err != nil {
			return &wrapError{fmt.Sprintf("error unmarshalling union struct: %v", err), err}
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := unmarshalValue(buf, s.Field(i), beginStructFieldCtx(ctx, s, i)); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal field %s: %v", s.Type().Field(i).Name, err), err}
		}
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
				return &wrapError{fmt.Sprintf("cannot read size of sized buffer: %v", err), err}
			}
			if !slice.CanSet() {
				return errors.New("cannot set slice")
			} else {
				slice.Set(reflect.MakeSlice(slice.Type(), int(size), int(size)))
			}
		}
		if _, err := io.ReadFull(buf, slice.Bytes()); err != nil {
			return &wrapError{fmt.Sprintf("cannot read byte slice directly from input buffer: %v", err), err}
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
			return &wrapError{fmt.Sprintf("cannot read length of list: %v", err), err}
		}
		if !slice.CanSet() {
			return errors.New("cannot set slice")
		} else {
			slice.Set(reflect.MakeSlice(slice.Type(), int(length), int(length)))
		}
	}

	for i := 0; i < slice.Len(); i++ {
		if err := unmarshalValue(buf, slice.Index(i), beginSliceElemCtx(ctx, slice)); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal value at index %d: %v", i, err), err}
		}
	}
	return nil
}

func unmarshalValue(buf io.Reader, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr && !val.CanAddr():
			return fmt.Errorf("cannot unmarshal non-addressable non-pointer type %s with custom marshaller", val.Type())
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		default:
			if val.IsNil() {
				val.Set(reflect.New(val.Type().Elem()))
			}
		}
		if err := val.Interface().(CustomMarshaller).Unmarshal(buf); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal type %s with custom marshaller: %v", origVal.Type(), err), err}
		}
		return nil
	}

	if ctx == nil {
		ctx = new(muContext)
	} else {
		ctx.depth++
	}

	if ctx.options.sized {
		if err := unmarshalSized(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal sized type %s: %v", val.Type(), err), err}
		}
		return nil
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := unmarshalPtr(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal pointer type %s: %v", val.Type(), err), err}
		}
	case reflect.Struct:
		if err := unmarshalStruct(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal struct type %s: %v", val.Type(), err), err}
		}
	case reflect.Slice:
		if err := unmarshalSlice(buf, val, ctx); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal slice type %s: %v", val.Type(), err), err}
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
		return fmt.Errorf("cannot unmarshal type %s: unsupported kind %s", val.Type(), val.Kind())
	default:
		if !val.CanAddr() {
			return fmt.Errorf("cannot unmarshal non-addressable type %s", val.Type())
		}
		if err := binary.Read(buf, binary.BigEndian, val.Addr().Interface()); err != nil {
			return &wrapError{fmt.Sprintf("cannot unmarshal type %s: read from buffer failed: %v", val.Type(), err), err}
		}
	}
	return nil
}

// MarshalToWriter marshals vals to buf in the TPM wire format, according to the rules specified in "Parameter marshalling and
// unmarshalling". A nil pointer encountered during marshalling causes the zero value for the type to be marshalled, unless the
// pointer is to a sized structure.
//
// If this function does not complete successfully, it will return an error. In this case, a partial result may have been written
// to buf.
func MarshalToWriter(buf io.Writer, vals ...interface{}) error {
	for _, val := range vals {
		if err := marshalValue(buf, reflect.ValueOf(val), nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalToBytes marshals vals to the TPM wire format, according to the rules specified in "Parameter marshalling and unmarshalling".
// A nil pointer encountered during marshalling causes the zero value for the type to be marshalled, unless the pointer is to a sized
// structure.
//
// If successful, this function returns the marshalled data. If this function does not complete successfully, it will return an error.
// In this case, no data will be returned.
func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := MarshalToWriter(buf, vals...); err != nil {
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
// If this function does not complete successfully, it will return an error. In this case, partial results may have been unmarshalled
// to the supplied destination values.
func UnmarshalFromReader(buf io.Reader, vals ...interface{}) error {
	for _, val := range vals {
		v := reflect.ValueOf(val)
		if v.Kind() != reflect.Ptr {
			return fmt.Errorf("cannot unmarshal to non-pointer type %s", v.Type())
		}

		if v.IsNil() {
			return fmt.Errorf("cannot unmarshal to nil pointer of type %s", v.Type())
		}

		if err := unmarshalValue(buf, v.Elem(), nil); err != nil {
			return err
		}
	}
	return nil
}

// UnmarshalFromBytes unmarshals data in the TPM wire format from b to vals, according to the rules specified in "Parameter
// marshalling and unmarshalling". The values supplied to this function must be pointers to the destination values. Nil pointer
// fields encountered during unmarshalling will result in memory being allocated for those values, unless the pointer represents a
// zero-sized sized struct. New slices will always be created - even if the caller pre-allocates them, unless it is a RawBytes type
// or a field with the `tpm2:"raw"` tag.
//
// If successful, this function returns the number of bytes consumed from b. If this function does not complete successfully, it will
// return an error and zero for the number of bytes consumed. In this case, partial results may have been unmarshalled to the
// supplied destination values.
func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	if err := UnmarshalFromReader(buf, vals...); err != nil {
		return 0, err
	}
	return len(b) - buf.Len(), nil
}
