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
	byteType             reflect.Type = reflect.TypeOf(byte(0))
	customMarshallerType reflect.Type = reflect.TypeOf((*CustomMarshaller)(nil)).Elem()
	rawSliceType         reflect.Type = reflect.TypeOf(RawSliceType{})
	unionType            reflect.Type = reflect.TypeOf((*Union)(nil)).Elem()
)

type CustomMarshaller interface {
	Marshal(buf io.Writer) error
	Unmarshal(buf io.Reader) error
}

type RawSliceType struct {
	Impl interface{}
}

func RawSlice(i interface{}) *RawSliceType {
	return &RawSliceType{i}
}

type Union interface {
	Select(selector interface{}) (string, error)
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
	return t.Implements(unionType)
}

func isSizedBuffer(t reflect.Type) bool {
	if t.Kind() != reflect.Slice {
		return false
	}
	return t.Elem().Kind() == reflect.Uint8
}

func isRawSlice(t reflect.Type) bool {
	return t == rawSliceType
}

func hasCustomMarshallerImpl(t reflect.Type) bool {
	if t.Kind() != reflect.Ptr {
		t = reflect.PtrTo(t)
	}
	return t.Implements(customMarshallerType)

}

func makeSizedStructReader(buf io.Reader) (io.Reader, error) {
	var size uint16
	// Sized structures have a 16-bit size field
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("cannot read size of sized struct: %v", err)
	}
	if size == 0 {
		return nil, nil
	}
	return io.LimitReader(buf, int64(size)), nil
}

type invalidSelectorError struct {
	selector interface{}
}

func (e invalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.selector)
}

type muOptions struct {
	selector string
	sized    bool
}

func parseFieldOptions(s string) muOptions {
	var opts muOptions
	for _, part := range strings.Split(s, ",") {
		switch {
		case strings.HasPrefix(part, "selector:"):
			opts.selector = part[9:]
		case part == "sized":
			opts.sized = true
		}
	}
	return opts
}

type muContext struct {
	depth      int
	container  reflect.Value
	parentType reflect.Type
	options    muOptions
}

func beginRawSliceCtx(ctx *muContext) *muContext {
	return &muContext{depth: ctx.depth, parentType: rawSliceType}
}

func beginStructFieldCtx(ctx *muContext, s reflect.Value, i int) *muContext {
	opts := parseFieldOptions(s.Type().Field(i).Tag.Get("tpm2"))
	return &muContext{depth: ctx.depth, container: s, parentType: s.Type(), options: opts}
}

func beginUnionFieldCtx(ctx *muContext, u reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: u, parentType: u.Type()}
}

func beginSliceElemCtx(ctx *muContext, s reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: s, parentType: s.Type()}
}

func beginPtrElemCtx(ctx *muContext, p reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: ctx.container, parentType: p.Type(), options: ctx.options}
}

func beginSizedStructCtx(ctx *muContext, p reflect.Value) *muContext {
	out := &muContext{depth: ctx.depth, container: ctx.container, parentType: p.Type(), options: ctx.options}
	out.options.sized = false
	return out
}

func beginInterfaceElemCtx(ctx *muContext, i reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: ctx.container, parentType: i.Type(), options: ctx.options}
}

func arrivedFromPointer(ctx *muContext, v reflect.Value) bool {
	return ctx.parentType == reflect.PtrTo(v.Type())
}

func marshalPtr(buf io.Writer, ptr reflect.Value, ctx *muContext) error {
	if ptr.IsNil() {
		if ctx.options.sized && ptr.Type().Elem().Kind() == reflect.Struct {
			// Nil pointers for sized structures are allowed - in this case, marshal a size
			// field of zero
			return binary.Write(buf, binary.BigEndian, uint16(0))
		}
		return errors.New("nil pointer")
	}

	return marshalValue(buf, ptr.Elem(), beginPtrElemCtx(ctx, ptr))
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
		return fmt.Errorf("invalid selector field name %s", ctx.options.selector)
	}

	// Select the union member to marshal based on the selector value from the parent container
	field, err := u.Interface().(Union).Select(selectorVal.Interface())
	if err != nil {
		return fmt.Errorf("cannot select union member: %v", err)
	}
	if field == "" {
		return nil
	}

	val := u.FieldByName(field)
	if !val.IsValid() {
		return fmt.Errorf("invalid union field name %s", field)
	}

	return marshalValue(buf, val, beginUnionFieldCtx(ctx, u))
}

func marshalStruct(buf io.Writer, s reflect.Value, ctx *muContext) error {
	if isRawSlice(s.Type()) {
		if ctx.container.IsValid() {
			return errors.New("RawSlice is inside another container")
		}

		f := s.Field(0).Elem()
		if f.Kind() != reflect.Slice {
			return fmt.Errorf("RawSlice contains invalid type %s (expected slice)", f.Type())
		}

		return marshalValue(buf, f, beginRawSliceCtx(ctx))
	}

	switch {
	case ctx.options.sized && isUnion(s.Type()):
		return errors.New("cannot be both sized and a union")
	case ctx.options.sized && !arrivedFromPointer(ctx, s):
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.container.Type())
	case ctx.options.sized:
		// Convert the sized struct to the non-sized type, marshal that to a temporary buffer and then
		// write it along with the 16-bit size field to the output buffer
		tmpBuf := new(bytes.Buffer)
		if err := marshalValue(tmpBuf, s, beginSizedStructCtx(ctx, s)); err != nil {
			return fmt.Errorf("cannot marshal sized struct: %v", err)
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
			return fmt.Errorf("cannot write size of sized struct to output buffer: %v", err)
		}
		if _, err := tmpBuf.WriteTo(buf); err != nil {
			return fmt.Errorf("cannot write marshalled sized struct to output buffer: %v", err)
		}
		return nil
	case isUnion(s.Type()):
		if err := marshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error marshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := marshalValue(buf, s.Field(i), beginStructFieldCtx(ctx, s, i)); err != nil {
			return fmt.Errorf("cannot marshal field %s: %v", s.Type().Field(i).Name, err)
		}
	}

	return nil
}

func marshalSlice(buf io.Writer, slice reflect.Value, ctx *muContext) error {
	// Marshal size field
	switch {
	case ctx.parentType == rawSliceType:
		// No size field - we've been instructed to marshal the slice as it is
	case isSizedBuffer(slice.Type()):
		// Sized byte-buffers have a 16-bit size field
		if err := binary.Write(buf, binary.BigEndian, uint16(slice.Len())); err != nil {
			return fmt.Errorf("cannot write size of sized buffer: %v", err)
		}
	default:
		// Treat all other slices as a list, which have a 32-bit size field
		if err := binary.Write(buf, binary.BigEndian, uint32(slice.Len())); err != nil {
			return fmt.Errorf("cannot write size of list: %v", err)
		}
	}

	if ctx.parentType == rawSliceType && slice.Type().Elem().Kind() == reflect.Uint8 {
		// Shortcut for raw byte-slice
		_, err := buf.Write(slice.Bytes())
		if err != nil {
			return fmt.Errorf("cannot write byte slice directly to output buffer: %v", err)
		}
		return nil
	}

	for i := 0; i < slice.Len(); i++ {
		if err := marshalValue(buf, slice.Index(i), beginSliceElemCtx(ctx, slice)); err != nil {
			return fmt.Errorf("cannot marshal value at index %d: %v", i, err)
		}
	}
	return nil
}

func marshalInterface(buf io.Writer, i reflect.Value, ctx *muContext) error {
	if i.Type().NumMethod() > 0 {
		return errors.New("interface contains a non-zero number of methods")
	}

	if err := marshalValue(buf, i.Elem(), beginInterfaceElemCtx(ctx, i)); err != nil {
		return fmt.Errorf("cannot marshal interface value: %v", err)
	}

	return nil
}

func marshalValue(buf io.Writer, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr && !val.CanAddr():
			return fmt.Errorf("cannot marshal non-addressable non-pointer type %s with custom "+
				"marshaller", val.Type())
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		case val.IsNil():
			return fmt.Errorf("cannot marshal nil pointer type %s with custom marshaller", val.Type())
		}
		if err := val.Interface().(CustomMarshaller).Marshal(buf); err != nil {
			return fmt.Errorf("cannot marshal type %s with custom marshaller: %v", origVal.Type(), err)
		}
		return nil
	}

	if ctx == nil {
		ctx = new(muContext)
	} else {
		ctx.depth++
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := marshalPtr(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot marshal pointer type %s: %v", val.Type(), err)
		}
	case reflect.Struct:
		if err := marshalStruct(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot marshal struct type %s: %v", val.Type(), err)
		}
	case reflect.Slice:
		if err := marshalSlice(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot marshal slice type %s: %v", val.Type(), err)
		}
	case reflect.Interface:
		if err := marshalInterface(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot marshal interface type %s: %v", val.Type(), err)
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Map, reflect.UnsafePointer:
		return fmt.Errorf("cannot marshal type %s: unsupported kind %s", val.Type(), val.Kind())
	default:
		if err := binary.Write(buf, binary.BigEndian, val.Interface()); err != nil {
			return fmt.Errorf("cannot marshal type %s: write to buffer failed: %v", val.Type(), err)
		}
	}
	return nil
}

func unmarshalPtr(buf io.Reader, ptr reflect.Value, ctx *muContext) error {
	if !ptr.CanSet() {
		return errors.New("unexported field")
	}

	srcBuf := buf

	if ctx.options.sized && ptr.Type().Elem().Kind() == reflect.Struct {
		b, err := makeSizedStructReader(buf)
		if err != nil {
			return err
		}
		if b == nil {
			return nil
		}
		srcBuf = b
	}

	ptr.Set(reflect.New(ptr.Type().Elem()))
	return unmarshalValue(srcBuf, ptr.Elem(), beginPtrElemCtx(ctx, ptr))
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
		return fmt.Errorf("invalid selector field name %s", ctx.options.selector)
	}

	// Select the union member to marshal based on the selector value from the parent container
	field, err := u.Interface().(Union).Select(selectorVal.Interface())
	if err != nil {
		return fmt.Errorf("cannot select union member: %v", err)
	}
	if field == "" {
		return nil
	}

	val := u.FieldByName(field)
	if !val.IsValid() {
		return fmt.Errorf("invalid union field name %s", field)
	}

	return unmarshalValue(buf, val, beginUnionFieldCtx(ctx, u))
}

func unmarshalStruct(buf io.Reader, s reflect.Value, ctx *muContext) error {
	if isRawSlice(s.Type()) {
		if ctx.container.IsValid() {
			return errors.New("RawSlice is inside another container")
		}

		f := s.Field(0).Elem()
		if f.Kind() != reflect.Slice {
			return fmt.Errorf("RawSlice contains invalid type %s (expected slice)", f.Type())
		}

		return unmarshalValue(buf, f, beginRawSliceCtx(ctx))
	}

	switch {
	case ctx.options.sized && isUnion(s.Type()):
		return errors.New("cannot be both sized and a union")
	case ctx.options.sized && !arrivedFromPointer(ctx, s):
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.container.Type())
	case ctx.options.sized:
		if err := unmarshalValue(buf, s, beginSizedStructCtx(ctx, s)); err != nil {
			return fmt.Errorf("cannot unmarshal sized struct: %v", err)
		}
		return nil
	case isUnion(s.Type()):
		if err := unmarshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error unmarshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := unmarshalValue(buf, s.Field(i), beginStructFieldCtx(ctx, s, i)); err != nil {
			return fmt.Errorf("cannot unmarshal field %s: %v", s.Type().Field(i).Name, err)
		}
	}
	return nil
}

func unmarshalSlice(buf io.Reader, slice reflect.Value, ctx *muContext) error {
	var l int
	switch {
	case ctx.parentType == rawSliceType:
		// No size field - unmarshalling requires a pre-allocated slice
		if slice.IsNil() {
			return errors.New("nil raw slice")
		}
	case isSizedBuffer(slice.Type()):
		// Sized byte-buffers have a 16-bit size field
		var tmp uint16
		if err := binary.Read(buf, binary.BigEndian, &tmp); err != nil {
			return fmt.Errorf("cannot read size of sized buffer: %v", err)
		}
		l = int(tmp)
	default:
		// Treat all other slices as a list, which have a 32-bit size field
		var tmp uint32
		if err := binary.Read(buf, binary.BigEndian, &tmp); err != nil {
			return fmt.Errorf("cannot read size of list: %v", err)
		}
		l = int(tmp)
	}

	// Allocate the slice
	if slice.IsNil() {
		if !slice.CanSet() {
			return errors.New("unexported field")
		}
		slice.Set(reflect.MakeSlice(slice.Type(), l, l))
	}

	if ctx.parentType == rawSliceType && slice.Type().Elem().Kind() == reflect.Uint8 {
		// Shortcut for raw byte-slice
		if _, err := io.ReadFull(buf, slice.Bytes()); err != nil {
			return fmt.Errorf("cannot read byte slice directly from input buffer: %v", err)
		}
		return nil
	}

	for i := 0; i < slice.Len(); i++ {
		if err := unmarshalValue(buf, slice.Index(i), beginSliceElemCtx(ctx, slice)); err != nil {
			return fmt.Errorf("cannot unmarshal value at index %d: %v", i, err)
		}
	}
	return nil
}

func unmarshalInterface(buf io.Reader, i reflect.Value, ctx *muContext) error {
	if !i.CanSet() {
		return errors.New("unexported field")
	}

	if i.Type().NumMethod() > 0 {
		return errors.New("interface contains a non-zero number of methods")
	}

	val := reflect.New(i.Elem().Type())
	if err := unmarshalValue(buf, val.Elem(), beginInterfaceElemCtx(ctx, i)); err != nil {
		return fmt.Errorf("cannot unmarshal interface value: %v", err)
	}
	i.Set(val.Elem())

	return nil
}

func unmarshalValue(buf io.Reader, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val.Type()) {
		origVal := val
		switch {
		case val.Kind() != reflect.Ptr && !val.CanAddr():
			return fmt.Errorf("cannot unmarshal non-addressable non-pointer type %s with custom "+
				"marshaller", val.Type())
		case val.Kind() != reflect.Ptr:
			val = val.Addr()
		default:
			val.Set(reflect.New(val.Type().Elem()))
		}
		if err := val.Interface().(CustomMarshaller).Unmarshal(buf); err != nil {
			return fmt.Errorf("cannot unmarshal type %s with custom marshaller: %v",
				origVal.Type(), err)
		}
		return nil
	}

	if ctx == nil {
		ctx = new(muContext)
	} else {
		ctx.depth++
	}

	switch val.Kind() {
	case reflect.Ptr:
		if err := unmarshalPtr(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot unmarshal pointer type %s: %v", val.Type(), err)
		}
	case reflect.Struct:
		if err := unmarshalStruct(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot unmarshal struct type %s: %v", val.Type(), err)
		}
	case reflect.Slice:
		if err := unmarshalSlice(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot unmarshal slice type %s: %v", val.Type(), err)
		}
	case reflect.Interface:
		if err := unmarshalInterface(buf, val, ctx); err != nil {
			return fmt.Errorf("cannot unmarshal interface type %s: %v", val.Type(), err)
		}
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Map, reflect.UnsafePointer:
		return fmt.Errorf("cannot unmarshal type %s: unsupported kind %s", val.Type(), val.Kind())
	default:
		if !val.CanAddr() {
			return fmt.Errorf("cannot unmarshal non-addressable type %s", val.Type())
		}
		if err := binary.Read(buf, binary.BigEndian, val.Addr().Interface()); err != nil {
			return fmt.Errorf("cannot unmarshal type %s: read from buffer failed: %v",
				val.Type(), err)
		}
	}
	return nil
}

func MarshalToWriter(buf io.Writer, vals ...interface{}) error {
	for _, val := range vals {
		if err := marshalValue(buf, reflect.ValueOf(val), nil); err != nil {
			return err
		}
	}
	return nil
}

func MarshalToBytes(vals ...interface{}) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := MarshalToWriter(buf, vals...); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

func UnmarshalFromBytes(b []byte, vals ...interface{}) (int, error) {
	buf := bytes.NewReader(b)
	if err := UnmarshalFromReader(buf, vals...); err != nil {
		return 0, err
	}
	return len(b) - buf.Len(), nil
}
