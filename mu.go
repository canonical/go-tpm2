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
)

var (
	byteType             reflect.Type = reflect.TypeOf(byte(0))
	customMarshallerType reflect.Type = reflect.TypeOf((*CustomMarshaller)(nil)).Elem()
	rawSliceType         reflect.Type = reflect.TypeOf(RawSliceType{})
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
	Select(selector interface{}, u reflect.Value) (reflect.Value, error)
}

type UnionContainer interface {
	Selector(field reflect.StructField) interface{}
}

type SizedStruct interface {
	UnsizedStructType() reflect.Type
}

func isUnionContainer(s reflect.Value) bool {
	_, hasInterface := s.Interface().(UnionContainer)
	return hasInterface
}

func isUnion(s reflect.Value) bool {
	_, hasInterface := s.Interface().(Union)
	return hasInterface
}

func isSizedStruct(s reflect.Value) bool {
	_, hasInterface := s.Interface().(SizedStruct)
	return hasInterface
}

func isSizedBuffer(s reflect.Value) bool {
	if s.Kind() != reflect.Slice {
		return false
	}
	return s.Type().Elem().Kind() == reflect.Uint8
}

func isRawSlice(s reflect.Value) bool {
	return s.Type() == rawSliceType
}

func hasCustomMarshallerImpl(val reflect.Value) bool {
	t := val.Type()
	if val.Kind() != reflect.Ptr {
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
	b := make([]byte, size)
	if _, err := io.ReadFull(buf, b); err != nil {
		return nil, fmt.Errorf("cannot read contents of sized struct: %v", err)
	}
	return bytes.NewReader(b), nil
}

type invalidSelectorError struct {
	selector interface{}
}

func (e invalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.selector)
}

type muContext struct {
	depth         int
	container     reflect.Value
	fieldInParent reflect.StructField
	parentType    reflect.Type
}

func beginRawSliceCtx(ctx *muContext) *muContext {
	return &muContext{depth: ctx.depth, parentType: rawSliceType}
}

func beginStructCtx(ctx *muContext, s reflect.Value, i int) *muContext {
	return &muContext{depth: ctx.depth, container: s, fieldInParent: s.Type().Field(i), parentType: s.Type()}
}

func beginUnionCtx(ctx *muContext, u reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: u, parentType: u.Type()}
}

func beginSliceCtx(ctx *muContext, s reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: s, parentType: s.Type()}
}

func beginPtrCtx(ctx *muContext, p reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, container: ctx.container, fieldInParent: ctx.fieldInParent,
		parentType: p.Type()}
}

func arrivedFromPointer(ctx *muContext, v reflect.Value) bool {
	return ctx.parentType == reflect.PtrTo(v.Type())
}

func marshalPtr(buf io.Writer, ptr reflect.Value, ctx *muContext) error {
	if ptr.IsNil() {
		tmp := reflect.New(ptr.Type().Elem())
		if isSizedStruct(tmp.Elem()) {
			// Nil pointers for sized structures are allowed - in this case, marshal a size
			// field of zero
			return binary.Write(buf, binary.BigEndian, uint16(0))
		}
		return errors.New("nil pointer")
	}

	return marshalValue(buf, ptr.Elem(), beginPtrCtx(ctx, ptr))
}

func marshalUnion(buf io.Writer, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		return errors.New("not inside a container")
	}
	if !isUnionContainer(ctx.container) {
		return errors.New("inside invalid container type")
	}

	// Select the union member to marshal based on the selector value from the parent container
	selector := ctx.container.Interface().(UnionContainer).Selector(ctx.fieldInParent)
	val, err := u.Interface().(Union).Select(selector, u)
	if err != nil {
		return fmt.Errorf("cannot select union member: %v", err)
	}
	if !val.IsValid() {
		return nil
	}

	return marshalValue(buf, val, beginUnionCtx(ctx, u))
}

func marshalStruct(buf io.Writer, s reflect.Value, ctx *muContext) error {
	if isRawSlice(s) {
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
	case isSizedStruct(s) && isUnion(s):
		return errors.New("cannot be both sized and a union")
	case isSizedStruct(s) && ctx.container.IsValid() && !arrivedFromPointer(ctx, s):
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.container.Type())
	case isSizedStruct(s):
		// Convert the sized struct to the non-sized type, marshal that to a temporary buffer and then
		// write it along with the 16-bit size field to the output buffer
		tmpBuf := new(bytes.Buffer)
		us := s.Convert(s.Interface().(SizedStruct).UnsizedStructType())
		if err := marshalStruct(tmpBuf, us, ctx); err != nil {
			return fmt.Errorf("cannot marshal sized struct: %v", err)
		}
		if err := binary.Write(buf, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
			return fmt.Errorf("cannot write size of sized struct to output buffer: %v", err)
		}
		if _, err := tmpBuf.WriteTo(buf); err != nil {
			return fmt.Errorf("cannot write marshalled sized struct to output buffer: %v", err)
		}
		return nil
	case isUnion(s):
		if err := marshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error marshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := marshalValue(buf, s.Field(i), beginStructCtx(ctx, s, i)); err != nil {
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
	case isSizedBuffer(slice):
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
		if err := marshalValue(buf, slice.Index(i), beginSliceCtx(ctx, slice)); err != nil {
			return fmt.Errorf("cannot marshal value at index %d: %v", i, err)
		}
	}
	return nil
}

func marshalValue(buf io.Writer, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val) {
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
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
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

	ptr.Set(reflect.New(ptr.Type().Elem()))
	srcBuf := buf

	if isSizedStruct(ptr.Elem()) {
		b, err := makeSizedStructReader(buf)
		// If the size of the sized struct is zero, clear the pointer
		if b == nil || err != nil {
			ptr.Set(reflect.Zero(ptr.Type()))
		}
		if err != nil {
			return err
		}
		if b == nil {
			return nil
		}
		srcBuf = b
	}

	return unmarshalValue(srcBuf, ptr.Elem(), beginPtrCtx(ctx, ptr))
}

func unmarshalUnion(buf io.Reader, u reflect.Value, ctx *muContext) error {
	if !ctx.container.IsValid() {
		return errors.New("not inside a container")
	}
	if !isUnionContainer(ctx.container) {
		return errors.New("inside invalid container type")
	}

	// Select the union member to marshal based on the selector value from the parent container
	selector := ctx.container.Interface().(UnionContainer).Selector(ctx.fieldInParent)
	val, err := u.Interface().(Union).Select(selector, u)
	if err != nil {
		return fmt.Errorf("cannot select union member: %v", err)
	}
	if !val.IsValid() {
		return nil
	}

	return unmarshalValue(buf, val, beginUnionCtx(ctx, u))
}

func unmarshalStruct(buf io.Reader, s reflect.Value, ctx *muContext) error {
	if isRawSlice(s) {
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
	case isSizedStruct(s) && isUnion(s):
		return errors.New("cannot be both sized and a union")
	case isSizedStruct(s) && ctx.container.IsValid() && !arrivedFromPointer(ctx, s):
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.container.Type())
	case isSizedStruct(s):
		srcBuf := buf
		if !arrivedFromPointer(ctx, s) {
			// The pointer unmarshalling creates the sized buffer reader for us
			b, err := makeSizedStructReader(buf)
			if err != nil {
				return err
			}
			if b == nil {
				return errors.New("sized struct cannot have zero size in this context")
			}
			srcBuf = b
		}
		t := reflect.PtrTo(s.Interface().(SizedStruct).UnsizedStructType())
		us := s.Addr().Convert(t).Elem()
		if err := unmarshalStruct(srcBuf, us, ctx); err != nil {
			return fmt.Errorf("cannot unmarshal sized struct: %v", err)
		}
		return nil
	case isUnion(s):
		if err := unmarshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error unmarshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := unmarshalValue(buf, s.Field(i), beginStructCtx(ctx, s, i)); err != nil {
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
	case isSizedBuffer(slice):
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
		if err := unmarshalValue(buf, slice.Index(i), beginSliceCtx(ctx, slice)); err != nil {
			return fmt.Errorf("cannot unmarshal value at index %d: %v", i, err)
		}
	}
	return nil
}

func unmarshalValue(buf io.Reader, val reflect.Value, ctx *muContext) error {
	if hasCustomMarshallerImpl(val) {
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
	case reflect.Array, reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.UnsafePointer:
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
