// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: mixer/adapter/circonus/config/config.proto

// The `circonus` adapter enables Istio to deliver metric data to the
// [Circonus](https://www.circonus.com) monitoring backend.
//
// This adapter supports the [metric template](https://istio.io/docs/reference/config/policy-and-telemetry/templates/metric/).

package config

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/gogo/protobuf/types"
	github_com_gogo_protobuf_types "github.com/gogo/protobuf/types"
	io "io"
	math "math"
	reflect "reflect"
	strconv "strconv"
	strings "strings"
	time "time"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf
var _ = time.Kitchen

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// The type of metric.
type Params_MetricInfo_Type int32

const (
	UNKNOWN      Params_MetricInfo_Type = 0
	COUNTER      Params_MetricInfo_Type = 1
	GAUGE        Params_MetricInfo_Type = 2
	DISTRIBUTION Params_MetricInfo_Type = 3
)

var Params_MetricInfo_Type_name = map[int32]string{
	0: "UNKNOWN",
	1: "COUNTER",
	2: "GAUGE",
	3: "DISTRIBUTION",
}

var Params_MetricInfo_Type_value = map[string]int32{
	"UNKNOWN":      0,
	"COUNTER":      1,
	"GAUGE":        2,
	"DISTRIBUTION": 3,
}

func (Params_MetricInfo_Type) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_a882fc6f8436c1a2, []int{0, 0, 0}
}

// Configuration format for the Circonus adapter.
type Params struct {
	// Circonus SubmissionURL to HTTPTrap check
	SubmissionUrl      string               `protobuf:"bytes,1,opt,name=submission_url,json=submissionUrl,proto3" json:"submission_url,omitempty"`
	SubmissionInterval time.Duration        `protobuf:"bytes,2,opt,name=submission_interval,json=submissionInterval,proto3,stdduration" json:"submission_interval"`
	Metrics            []*Params_MetricInfo `protobuf:"bytes,3,rep,name=metrics,proto3" json:"metrics,omitempty"`
}

func (m *Params) Reset()      { *m = Params{} }
func (*Params) ProtoMessage() {}
func (*Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_a882fc6f8436c1a2, []int{0}
}
func (m *Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params.Merge(m, src)
}
func (m *Params) XXX_Size() int {
	return m.Size()
}
func (m *Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Params proto.InternalMessageInfo

// Describes how to represent a metric
type Params_MetricInfo struct {
	// name
	Name string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Type Params_MetricInfo_Type `protobuf:"varint,2,opt,name=type,proto3,enum=adapter.circonus.config.Params_MetricInfo_Type" json:"type,omitempty"`
}

func (m *Params_MetricInfo) Reset()      { *m = Params_MetricInfo{} }
func (*Params_MetricInfo) ProtoMessage() {}
func (*Params_MetricInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_a882fc6f8436c1a2, []int{0, 0}
}
func (m *Params_MetricInfo) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Params_MetricInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Params_MetricInfo.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *Params_MetricInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Params_MetricInfo.Merge(m, src)
}
func (m *Params_MetricInfo) XXX_Size() int {
	return m.Size()
}
func (m *Params_MetricInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_Params_MetricInfo.DiscardUnknown(m)
}

var xxx_messageInfo_Params_MetricInfo proto.InternalMessageInfo

func init() {
	proto.RegisterEnum("adapter.circonus.config.Params_MetricInfo_Type", Params_MetricInfo_Type_name, Params_MetricInfo_Type_value)
	proto.RegisterType((*Params)(nil), "adapter.circonus.config.Params")
	proto.RegisterType((*Params_MetricInfo)(nil), "adapter.circonus.config.Params.MetricInfo")
}

func init() {
	proto.RegisterFile("mixer/adapter/circonus/config/config.proto", fileDescriptor_a882fc6f8436c1a2)
}

var fileDescriptor_a882fc6f8436c1a2 = []byte{
	// 404 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x90, 0xcd, 0xaa, 0xd3, 0x40,
	0x1c, 0xc5, 0x67, 0xda, 0xda, 0xda, 0xa9, 0x96, 0x30, 0x0a, 0xd6, 0x2e, 0xa6, 0xa5, 0x20, 0x94,
	0x2e, 0x26, 0x50, 0xd7, 0x82, 0xf6, 0x83, 0x12, 0xc4, 0x54, 0x62, 0x82, 0xe0, 0x46, 0xd2, 0x74,
	0x1a, 0x06, 0x92, 0x4c, 0x98, 0x24, 0x62, 0x77, 0x3e, 0x82, 0x4b, 0x1f, 0xc0, 0x85, 0x8f, 0xd2,
	0x65, 0x97, 0x5d, 0xa9, 0x49, 0x37, 0x2e, 0x8b, 0x4f, 0x70, 0x69, 0x92, 0xd2, 0xbb, 0xb9, 0x70,
	0x57, 0xf3, 0xff, 0xf8, 0x1d, 0xce, 0xf9, 0x0f, 0x1a, 0xf9, 0xfc, 0x2b, 0x93, 0xaa, 0xbd, 0xb6,
	0xc3, 0x98, 0x49, 0xd5, 0xe1, 0xd2, 0x11, 0x41, 0x12, 0xa9, 0x8e, 0x08, 0x36, 0xdc, 0x2d, 0x1f,
	0x1a, 0x4a, 0x11, 0x0b, 0xfc, 0xac, 0xa4, 0xe8, 0x85, 0xa2, 0xc5, 0xba, 0xfb, 0xd4, 0x15, 0xae,
	0xc8, 0x19, 0xf5, 0x5c, 0x15, 0x78, 0x97, 0xb8, 0x42, 0xb8, 0x1e, 0x53, 0xf3, 0x6e, 0x95, 0x6c,
	0xd4, 0x75, 0x22, 0xed, 0x98, 0x8b, 0xa0, 0xd8, 0x0f, 0xfe, 0x57, 0x50, 0xfd, 0xbd, 0x2d, 0x6d,
	0x3f, 0xc2, 0x2f, 0x50, 0x3b, 0x4a, 0x56, 0x3e, 0x8f, 0x22, 0x2e, 0x82, 0xcf, 0x89, 0xf4, 0x3a,
	0xb0, 0x0f, 0x87, 0x4d, 0xe3, 0xf1, 0x75, 0x6a, 0x49, 0x0f, 0x9b, 0xe8, 0xc9, 0x2d, 0x8c, 0x07,
	0x31, 0x93, 0x5f, 0x6c, 0xaf, 0x53, 0xe9, 0xc3, 0x61, 0x6b, 0xfc, 0x9c, 0x16, 0x7e, 0xf4, 0xe2,
	0x47, 0x67, 0xa5, 0xdf, 0xe4, 0xe1, 0xee, 0x77, 0x0f, 0xfc, 0xf8, 0xd3, 0x83, 0x06, 0xbe, 0xea,
	0xb5, 0x52, 0x8e, 0x67, 0xa8, 0xe1, 0xb3, 0x58, 0x72, 0x27, 0xea, 0x54, 0xfb, 0xd5, 0x61, 0x6b,
	0x3c, 0xa2, 0x77, 0x1c, 0x4a, 0x8b, 0xb8, 0xf4, 0x5d, 0x8e, 0x6b, 0xc1, 0x46, 0x18, 0x17, 0x69,
	0xf7, 0x27, 0x44, 0xe8, 0x3a, 0xc7, 0x18, 0xd5, 0x02, 0xdb, 0x67, 0xe5, 0x1d, 0x79, 0x8d, 0xa7,
	0xa8, 0x16, 0x6f, 0x43, 0x96, 0xe7, 0x6d, 0x8f, 0xd5, 0xfb, 0xbb, 0x50, 0x73, 0x1b, 0x32, 0x23,
	0x17, 0x0f, 0x5e, 0xa1, 0xda, 0xb9, 0xc3, 0x2d, 0xd4, 0xb0, 0xf4, 0xb7, 0xfa, 0xf2, 0xa3, 0xae,
	0x80, 0x73, 0x33, 0x5d, 0x5a, 0xba, 0x39, 0x37, 0x14, 0x88, 0x9b, 0xe8, 0xc1, 0xe2, 0x8d, 0xb5,
	0x98, 0x2b, 0x15, 0xac, 0xa0, 0x47, 0x33, 0xed, 0x83, 0x69, 0x68, 0x13, 0xcb, 0xd4, 0x96, 0xba,
	0x52, 0x9d, 0xbc, 0xde, 0xa5, 0x04, 0xec, 0x53, 0x02, 0x0e, 0x29, 0x01, 0xa7, 0x94, 0x80, 0x6f,
	0x19, 0x81, 0xbf, 0x32, 0x02, 0x76, 0x19, 0x81, 0xfb, 0x8c, 0xc0, 0xbf, 0x19, 0x81, 0xff, 0x32,
	0x02, 0x4e, 0x19, 0x81, 0xdf, 0x8f, 0x04, 0xec, 0x8f, 0x04, 0x1c, 0x8e, 0x04, 0x7c, 0xaa, 0x17,
	0xe9, 0x56, 0xf5, 0xfc, 0x7f, 0x5f, 0xde, 0x04, 0x00, 0x00, 0xff, 0xff, 0x34, 0xfd, 0xfb, 0xf4,
	0x3a, 0x02, 0x00, 0x00,
}

func (x Params_MetricInfo_Type) String() string {
	s, ok := Params_MetricInfo_Type_name[int32(x)]
	if ok {
		return s
	}
	return strconv.Itoa(int(x))
}
func (m *Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.SubmissionUrl) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.SubmissionUrl)))
		i += copy(dAtA[i:], m.SubmissionUrl)
	}
	dAtA[i] = 0x12
	i++
	i = encodeVarintConfig(dAtA, i, uint64(github_com_gogo_protobuf_types.SizeOfStdDuration(m.SubmissionInterval)))
	n1, err := github_com_gogo_protobuf_types.StdDurationMarshalTo(m.SubmissionInterval, dAtA[i:])
	if err != nil {
		return 0, err
	}
	i += n1
	if len(m.Metrics) > 0 {
		for _, msg := range m.Metrics {
			dAtA[i] = 0x1a
			i++
			i = encodeVarintConfig(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	return i, nil
}

func (m *Params_MetricInfo) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Params_MetricInfo) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintConfig(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if m.Type != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintConfig(dAtA, i, uint64(m.Type))
	}
	return i, nil
}

func encodeVarintConfig(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.SubmissionUrl)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	l = github_com_gogo_protobuf_types.SizeOfStdDuration(m.SubmissionInterval)
	n += 1 + l + sovConfig(uint64(l))
	if len(m.Metrics) > 0 {
		for _, e := range m.Metrics {
			l = e.Size()
			n += 1 + l + sovConfig(uint64(l))
		}
	}
	return n
}

func (m *Params_MetricInfo) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovConfig(uint64(l))
	}
	if m.Type != 0 {
		n += 1 + sovConfig(uint64(m.Type))
	}
	return n
}

func sovConfig(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozConfig(x uint64) (n int) {
	return sovConfig(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *Params) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params{`,
		`SubmissionUrl:` + fmt.Sprintf("%v", this.SubmissionUrl) + `,`,
		`SubmissionInterval:` + strings.Replace(strings.Replace(this.SubmissionInterval.String(), "Duration", "types.Duration", 1), `&`, ``, 1) + `,`,
		`Metrics:` + strings.Replace(fmt.Sprintf("%v", this.Metrics), "Params_MetricInfo", "Params_MetricInfo", 1) + `,`,
		`}`,
	}, "")
	return s
}
func (this *Params_MetricInfo) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&Params_MetricInfo{`,
		`Name:` + fmt.Sprintf("%v", this.Name) + `,`,
		`Type:` + fmt.Sprintf("%v", this.Type) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringConfig(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubmissionUrl", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SubmissionUrl = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SubmissionInterval", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := github_com_gogo_protobuf_types.StdDurationUnmarshal(&m.SubmissionInterval, dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metrics", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Metrics = append(m.Metrics, &Params_MetricInfo{})
			if err := m.Metrics[len(m.Metrics)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *Params_MetricInfo) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: MetricInfo: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: MetricInfo: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthConfig
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthConfig
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Type", wireType)
			}
			m.Type = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Type |= Params_MetricInfo_Type(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipConfig(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthConfig
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipConfig(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowConfig
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
			return iNdEx, nil
		case 1:
			iNdEx += 8
			return iNdEx, nil
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowConfig
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthConfig
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthConfig
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowConfig
					}
					if iNdEx >= l {
						return 0, io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					innerWire |= (uint64(b) & 0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				innerWireType := int(innerWire & 0x7)
				if innerWireType == 4 {
					break
				}
				next, err := skipConfig(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthConfig
				}
			}
			return iNdEx, nil
		case 4:
			return iNdEx, nil
		case 5:
			iNdEx += 4
			return iNdEx, nil
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
	}
	panic("unreachable")
}

var (
	ErrInvalidLengthConfig = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowConfig   = fmt.Errorf("proto: integer overflow")
)
