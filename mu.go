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
)

type CustomMarshaller interface {
	Marshal(buf io.Writer) error
	Unmarshal(buf io.Reader) error
}

type SliceType int
type StructFlags int

const (
	SliceTypeSizedBufferU16 SliceType = iota
	SliceTypeSizedBufferU8
	SliceTypeList
)

const (
	StructFlagSized StructFlags = 1 << iota
	StructFlagContainsUnion
	StructFlagUnion
)

func isStructTypeWithUnion(s reflect.Value) bool {
	if s.Kind() != reflect.Struct {
		return false
	}
	trait, hasTrait := s.Interface().(StructTrait)
	if !hasTrait {
		return false
	}
	return trait.StructFlags()&StructFlagContainsUnion > 0
}

func isSizedStruct(s reflect.Value) bool {
	if s.Kind() != reflect.Struct {
		return false
	}
	trait, hasTrait := s.Interface().(StructTrait)
	if !hasTrait {
		return false
	}
	return trait.StructFlags()&StructFlagSized > 0
}

func isUnion(s reflect.Value) bool {
	if s.Kind() != reflect.Struct {
		return false
	}
	trait, hasTrait := s.Interface().(StructTrait)
	if !hasTrait {
		return false
	}
	return trait.StructFlags()&StructFlagUnion > 0
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
	if err := binary.Read(buf, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("cannot read size of sized struct: %v", err)
	}
	if size == 0 {
		return nil, nil
	}
	b := make([]byte, size)
	n, err := buf.Read(b)
	if err != nil {
		return nil, fmt.Errorf("cannot read contents of sized struct: %v", err)
	}
	if n < int(size) {
		return nil, fmt.Errorf("cannot read contents of sized struct: %v", io.EOF)
	}
	return bytes.NewReader(b), nil
}

type RawSliceType struct {
	Impl interface{}
}

func RawSlice(i interface{}) *RawSliceType {
	return &RawSliceType{i}
}

type SliceTrait interface {
	SliceType() SliceType
}

type StructTrait interface {
	StructFlags() StructFlags
}

type invalidSelectorError struct {
	selector interface{}
}

func (e invalidSelectorError) Error() string {
	return fmt.Sprintf("invalid selector value: %v", e.selector)
}

type Union interface {
	Select(selector interface{}, u reflect.Value) (reflect.Value, error)
}

type UnionContainer interface {
	Selector(field reflect.StructField) interface{}
}

type muContext struct {
	depth            int
	parent           reflect.Value
	fieldInParent    reflect.StructField
	parentIsRawSlice bool
	fromPointer      bool
}

func beginRawSliceCtx(ctx *muContext) *muContext {
	return &muContext{depth: ctx.depth, parentIsRawSlice: true}
}

func beginStructCtx(ctx *muContext, s reflect.Value, i int) *muContext {
	return &muContext{depth: ctx.depth, parent: s, fieldInParent: s.Type().Field(i)}
}

func beginUnionCtx(ctx *muContext, u reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, parent: u}
}

func beginSliceCtx(ctx *muContext, s reflect.Value) *muContext {
	return &muContext{depth: ctx.depth, parent: s}
}

func beginPtrCtx(ctx *muContext) *muContext {
	return &muContext{depth: ctx.depth, parent: ctx.parent, fieldInParent: ctx.fieldInParent,
		fromPointer: true}
}

func marshalPtr(buf io.Writer, ptr reflect.Value, ctx *muContext) error {
	if ptr.IsNil() {
		tmp := reflect.New(ptr.Type().Elem())
		if isSizedStruct(tmp.Elem()) {
			return binary.Write(buf, binary.BigEndian, uint16(0))
		}
		return errors.New("nil pointer")
	}

	return marshalValue(buf, ptr.Elem(), beginPtrCtx(ctx))
}

func marshalUnion(buf io.Writer, u reflect.Value, ctx *muContext) error {
	if !ctx.parent.IsValid() {
		return errors.New("not inside a container")
	}
	if !isStructTypeWithUnion(ctx.parent) {
		return errors.New("inside invalid container type")
	}

	selector := ctx.parent.Interface().(UnionContainer).Selector(ctx.fieldInParent)
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
	if s.Type() == reflect.TypeOf(RawSliceType{}) {
		if ctx.parent.IsValid() {
			return errors.New("RawSlice is inside another container")
		}

		f := s.Field(0).Elem()
		if f.Kind() != reflect.Slice {
			return fmt.Errorf("RawSlice contains invalid type %s (expected slice)", f.Type())
		}

		return marshalValue(buf, f, beginRawSliceCtx(ctx))
	}

	dstBuf := buf
	var tmpBuf *bytes.Buffer

	switch {
	case isSizedStruct(s) && isUnion(s):
		return errors.New("cannot be both sized and a union")
	case isSizedStruct(s) && !ctx.fromPointer && ctx.parent.IsValid():
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.parent.Type())
	case isSizedStruct(s):
		tmpBuf = new(bytes.Buffer)
		dstBuf = tmpBuf
	case isUnion(s):
		if err := marshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error marshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := marshalValue(dstBuf, s.Field(i), beginStructCtx(ctx, s, i)); err != nil {
			return fmt.Errorf("cannot marshal field %s: %v", s.Type().Field(i).Name, err)
		}
	}

	if tmpBuf == nil {
		return nil
	}

	if err := binary.Write(buf, binary.BigEndian, uint16(tmpBuf.Len())); err != nil {
		return fmt.Errorf("cannot write size of sized struct to output buffer: %v", err)
	}

	n, err := buf.Write(tmpBuf.Bytes())
	if err != nil {
		return fmt.Errorf("cannot write marshalled sized struct to output buffer: %v", err)
	}
	if n != tmpBuf.Len() {
		return errors.New("cannot write entire marshalled sized struct to output buffer")
	}
	return nil
}

func marshalSlice(buf io.Writer, slice reflect.Value, ctx *muContext) error {
	if trait, hasTrait := slice.Interface().(SliceTrait); hasTrait {
		switch trait.SliceType() {
		case SliceTypeSizedBufferU16:
			if err := binary.Write(buf, binary.BigEndian, uint16(slice.Len())); err != nil {
				return fmt.Errorf("cannot write size of sized buffer: %v", err)
			}
		case SliceTypeSizedBufferU8:
			if err := binary.Write(buf, binary.BigEndian, uint8(slice.Len())); err != nil {
				return fmt.Errorf("cannot write size of sized buffer: %v", err)
			}
		case SliceTypeList:
			if err := binary.Write(buf, binary.BigEndian, uint32(slice.Len())); err != nil {
				return fmt.Errorf("cannot write size of list: %v", err)
			}
		default:
			return fmt.Errorf("invalid SliceType %v", trait.SliceType())
		}
	} else if !ctx.parentIsRawSlice {
		return errors.New("missing SliceTrait implementation")
	} else if slice.Type().Elem() == byteType {
		n, err := buf.Write(slice.Bytes())
		if err != nil {
			return fmt.Errorf("cannot write byte slice directly to output buffer: %v", err)
		}
		if n < slice.Len() {
			return errors.New("cannot write entire byte slice directly to output buffer")
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

	return unmarshalValue(srcBuf, ptr.Elem(), beginPtrCtx(ctx))
}

func unmarshalUnion(buf io.Reader, u reflect.Value, ctx *muContext) error {
	if !ctx.parent.IsValid() {
		return errors.New("not inside a container")
	}
	if !isStructTypeWithUnion(ctx.parent) {
		return errors.New("inside invalid container type")
	}

	selector := ctx.parent.Interface().(UnionContainer).Selector(ctx.fieldInParent)
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
	if s.Type() == reflect.TypeOf(RawSliceType{}) {
		if ctx.parent.IsValid() {
			return errors.New("RawSlice is inside another container")
		}

		f := s.Field(0).Elem()
		if f.Kind() != reflect.Slice {
			return fmt.Errorf("RawSlice contains invalid type %s (expected slice)", f.Type())
		}

		return unmarshalValue(buf, f, beginRawSliceCtx(ctx))
	}

	srcBuf := buf

	switch {
	case isSizedStruct(s) && isUnion(s):
		return errors.New("cannot be both sized and a union")
	case isSizedStruct(s) && !ctx.fromPointer && ctx.parent.IsValid():
		return fmt.Errorf("sized struct inside container type %s is not referenced via a pointer",
			ctx.parent.Type())
	case isSizedStruct(s) && !ctx.fromPointer:
		b, err := makeSizedStructReader(buf)
		if err != nil {
			return err
		}
		if b == nil {
			return errors.New("sized struct cannot have zero size in this context")
		}
		srcBuf = b
	case isUnion(s):
		if err := unmarshalUnion(buf, s, ctx); err != nil {
			return fmt.Errorf("error unmarshalling union struct: %v", err)
		}
		return nil
	}

	for i := 0; i < s.NumField(); i++ {
		if err := unmarshalValue(srcBuf, s.Field(i), beginStructCtx(ctx, s, i)); err != nil {
			return fmt.Errorf("cannot unmarshal field %s: %v", s.Type().Field(i).Name, err)
		}
	}
	return nil
}

func unmarshalSlice(buf io.Reader, slice reflect.Value, ctx *muContext) error {
	var l int
	if trait, hasTrait := slice.Interface().(SliceTrait); hasTrait {
		switch trait.SliceType() {
		case SliceTypeSizedBufferU16:
			var tmp uint16
			if err := binary.Read(buf, binary.BigEndian, &tmp); err != nil {
				return fmt.Errorf("cannot read size of sized buffer: %v", err)
			}
			l = int(tmp)
		case SliceTypeSizedBufferU8:
			var tmp uint8
			if err := binary.Read(buf, binary.BigEndian, &tmp); err != nil {
				return fmt.Errorf("cannot read size of sized buffer: %v", err)
			}
			l = int(tmp)
		case SliceTypeList:
			var tmp uint32
			if err := binary.Read(buf, binary.BigEndian, &tmp); err != nil {
				return fmt.Errorf("cannot read size of list: %v", err)
			}
			l = int(tmp)
		default:
			return fmt.Errorf("invalid SliceType %v", trait.SliceType())
		}
	} else if !ctx.parentIsRawSlice {
		return errors.New("missing SliceTrait implementation")
	} else if slice.IsNil() {
		return errors.New("nil raw slice")
	} else if slice.Type().Elem() == byteType {
		n, err := buf.Read(slice.Bytes())
		if err != nil {
			return fmt.Errorf("cannot read byte slice directly from input buffer: %v", err)
		}
		if n < slice.Len() {
			return fmt.Errorf("cannot read byte slice directly from input buffer: %v", io.EOF)
		}
		return nil
	}

	if slice.IsNil() {
		if !slice.CanSet() {
			return errors.New("unexported field")
		}
		slice.Set(reflect.MakeSlice(slice.Type(), l, l))
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
