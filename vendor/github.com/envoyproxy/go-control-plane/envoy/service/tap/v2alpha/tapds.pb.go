// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/service/tap/v2alpha/tapds.proto

package envoy_service_tap_v2alpha

import (
	context "context"
	fmt "fmt"
	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	_ "github.com/gogo/googleapis/google/api"
	proto "github.com/gogo/protobuf/proto"
	grpc "google.golang.org/grpc"
	io "io"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// [#not-implemented-hide:] A tap resource is essentially a tap configuration with a name
// The filter TapDS config references this name.
type TapResource struct {
	// The name of the tap configuration.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Tap config to apply
	Config               *TapConfig `protobuf:"bytes,2,opt,name=config,proto3" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *TapResource) Reset()         { *m = TapResource{} }
func (m *TapResource) String() string { return proto.CompactTextString(m) }
func (*TapResource) ProtoMessage()    {}
func (*TapResource) Descriptor() ([]byte, []int) {
	return fileDescriptor_4eef591ebf2a5317, []int{0}
}
func (m *TapResource) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TapResource) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TapResource.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *TapResource) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TapResource.Merge(m, src)
}
func (m *TapResource) XXX_Size() int {
	return m.Size()
}
func (m *TapResource) XXX_DiscardUnknown() {
	xxx_messageInfo_TapResource.DiscardUnknown(m)
}

var xxx_messageInfo_TapResource proto.InternalMessageInfo

func (m *TapResource) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *TapResource) GetConfig() *TapConfig {
	if m != nil {
		return m.Config
	}
	return nil
}

func init() {
	proto.RegisterType((*TapResource)(nil), "envoy.service.tap.v2alpha.TapResource")
}

func init() {
	proto.RegisterFile("envoy/service/tap/v2alpha/tapds.proto", fileDescriptor_4eef591ebf2a5317)
}

var fileDescriptor_4eef591ebf2a5317 = []byte{
	// 378 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x92, 0xbf, 0x4e, 0x2a, 0x41,
	0x14, 0xc6, 0xef, 0xec, 0x25, 0x24, 0x0c, 0x05, 0x37, 0x7b, 0x8b, 0x0b, 0x84, 0xbb, 0x97, 0x70,
	0x51, 0x89, 0xc5, 0xac, 0x59, 0x3b, 0x62, 0x05, 0xc4, 0x9a, 0x2c, 0x34, 0x56, 0xe6, 0xb0, 0x8c,
	0x30, 0x66, 0x77, 0x66, 0xdc, 0x19, 0x36, 0xd0, 0xfa, 0x0a, 0xbe, 0x8d, 0x95, 0xa5, 0x95, 0x31,
	0xf1, 0x05, 0x0c, 0xb1, 0xf1, 0x2d, 0xcc, 0xfe, 0x81, 0x88, 0x66, 0xad, 0xec, 0x4e, 0xf6, 0x7c,
	0xdf, 0x6f, 0xcf, 0x99, 0xef, 0xe0, 0x3d, 0xca, 0x23, 0xb1, 0xb2, 0x15, 0x0d, 0x23, 0xe6, 0x51,
	0x5b, 0x83, 0xb4, 0x23, 0x07, 0x7c, 0x39, 0x87, 0xb8, 0x9e, 0x2a, 0x22, 0x43, 0xa1, 0x85, 0x59,
	0x4b, 0x64, 0x24, 0x93, 0x11, 0x0d, 0x92, 0x64, 0xb2, 0x7a, 0x23, 0x25, 0x80, 0x64, 0x76, 0xe4,
	0xd8, 0x53, 0xa6, 0x3c, 0x11, 0xd1, 0x70, 0x95, 0x1a, 0xeb, 0xfb, 0xf9, 0x7c, 0x4f, 0x04, 0x81,
	0xe0, 0x99, 0xee, 0x4f, 0x04, 0x3e, 0x9b, 0x82, 0xa6, 0xf6, 0xa6, 0xc8, 0x1a, 0x8d, 0x99, 0x10,
	0x33, 0x9f, 0x26, 0x7c, 0xe0, 0x5c, 0x68, 0xd0, 0x4c, 0xf0, 0x6c, 0xae, 0xd6, 0x25, 0x2e, 0x8f,
	0x41, 0xba, 0x54, 0x89, 0x45, 0xe8, 0x51, 0xf3, 0x2f, 0x2e, 0x70, 0x08, 0x68, 0x15, 0x35, 0x51,
	0xa7, 0xd4, 0x2b, 0xdd, 0xbe, 0xde, 0xfd, 0x2c, 0x84, 0x46, 0x13, 0xb9, 0xc9, 0x67, 0xf3, 0x04,
	0x17, 0x3d, 0xc1, 0x2f, 0xd8, 0xac, 0x6a, 0x34, 0x51, 0xa7, 0xec, 0xb4, 0x49, 0xee, 0x5a, 0x64,
	0x0c, 0xb2, 0x9f, 0x68, 0xdd, 0xcc, 0xe3, 0x3c, 0x18, 0xf8, 0xf7, 0x18, 0xe4, 0x60, 0xb3, 0xe1,
	0x28, 0x75, 0x99, 0x67, 0xf8, 0xd7, 0x48, 0x87, 0x14, 0x82, 0xad, 0x45, 0x99, 0x56, 0x46, 0x06,
	0xc9, 0x48, 0xe4, 0x90, 0xad, 0xc7, 0xa5, 0x57, 0x0b, 0xaa, 0x74, 0xfd, 0x5f, 0x6e, 0x5f, 0x49,
	0xc1, 0x15, 0x6d, 0xfd, 0xe8, 0xa0, 0x23, 0x64, 0x4e, 0x70, 0x65, 0x40, 0x7d, 0x0d, 0xef, 0xc8,
	0xff, 0x3f, 0x38, 0xe3, 0xf6, 0x27, 0x7c, 0xfb, 0x6b, 0xd1, 0xce, 0x3f, 0x96, 0xb8, 0x72, 0x4a,
	0xb5, 0x37, 0xff, 0xce, 0xe9, 0xdb, 0xd7, 0x4f, 0x2f, 0x37, 0x86, 0xd5, 0xaa, 0xed, 0x9c, 0x44,
	0x57, 0x83, 0x3c, 0x4f, 0x1f, 0x53, 0x75, 0xd1, 0x61, 0xaf, 0x7f, 0xbf, 0xb6, 0xd0, 0xe3, 0xda,
	0x42, 0xcf, 0x6b, 0x0b, 0xe1, 0x03, 0x26, 0x52, 0xac, 0x0c, 0xc5, 0x72, 0x95, 0x9f, 0x4c, 0x0f,
	0xc7, 0x21, 0xa8, 0x61, 0x9c, 0xff, 0x10, 0x4d, 0x8a, 0xc9, 0x21, 0x1c, 0xbf, 0x05, 0x00, 0x00,
	0xff, 0xff, 0x6a, 0x56, 0x3e, 0xeb, 0xc9, 0x02, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// TapDiscoveryServiceClient is the client API for TapDiscoveryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TapDiscoveryServiceClient interface {
	StreamTapConfigs(ctx context.Context, opts ...grpc.CallOption) (TapDiscoveryService_StreamTapConfigsClient, error)
	DeltaTapConfigs(ctx context.Context, opts ...grpc.CallOption) (TapDiscoveryService_DeltaTapConfigsClient, error)
	FetchTapConfigs(ctx context.Context, in *v2.DiscoveryRequest, opts ...grpc.CallOption) (*v2.DiscoveryResponse, error)
}

type tapDiscoveryServiceClient struct {
	cc *grpc.ClientConn
}

func NewTapDiscoveryServiceClient(cc *grpc.ClientConn) TapDiscoveryServiceClient {
	return &tapDiscoveryServiceClient{cc}
}

func (c *tapDiscoveryServiceClient) StreamTapConfigs(ctx context.Context, opts ...grpc.CallOption) (TapDiscoveryService_StreamTapConfigsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TapDiscoveryService_serviceDesc.Streams[0], "/envoy.service.tap.v2alpha.TapDiscoveryService/StreamTapConfigs", opts...)
	if err != nil {
		return nil, err
	}
	x := &tapDiscoveryServiceStreamTapConfigsClient{stream}
	return x, nil
}

type TapDiscoveryService_StreamTapConfigsClient interface {
	Send(*v2.DiscoveryRequest) error
	Recv() (*v2.DiscoveryResponse, error)
	grpc.ClientStream
}

type tapDiscoveryServiceStreamTapConfigsClient struct {
	grpc.ClientStream
}

func (x *tapDiscoveryServiceStreamTapConfigsClient) Send(m *v2.DiscoveryRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tapDiscoveryServiceStreamTapConfigsClient) Recv() (*v2.DiscoveryResponse, error) {
	m := new(v2.DiscoveryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *tapDiscoveryServiceClient) DeltaTapConfigs(ctx context.Context, opts ...grpc.CallOption) (TapDiscoveryService_DeltaTapConfigsClient, error) {
	stream, err := c.cc.NewStream(ctx, &_TapDiscoveryService_serviceDesc.Streams[1], "/envoy.service.tap.v2alpha.TapDiscoveryService/DeltaTapConfigs", opts...)
	if err != nil {
		return nil, err
	}
	x := &tapDiscoveryServiceDeltaTapConfigsClient{stream}
	return x, nil
}

type TapDiscoveryService_DeltaTapConfigsClient interface {
	Send(*v2.DeltaDiscoveryRequest) error
	Recv() (*v2.DeltaDiscoveryResponse, error)
	grpc.ClientStream
}

type tapDiscoveryServiceDeltaTapConfigsClient struct {
	grpc.ClientStream
}

func (x *tapDiscoveryServiceDeltaTapConfigsClient) Send(m *v2.DeltaDiscoveryRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *tapDiscoveryServiceDeltaTapConfigsClient) Recv() (*v2.DeltaDiscoveryResponse, error) {
	m := new(v2.DeltaDiscoveryResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *tapDiscoveryServiceClient) FetchTapConfigs(ctx context.Context, in *v2.DiscoveryRequest, opts ...grpc.CallOption) (*v2.DiscoveryResponse, error) {
	out := new(v2.DiscoveryResponse)
	err := c.cc.Invoke(ctx, "/envoy.service.tap.v2alpha.TapDiscoveryService/FetchTapConfigs", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TapDiscoveryServiceServer is the server API for TapDiscoveryService service.
type TapDiscoveryServiceServer interface {
	StreamTapConfigs(TapDiscoveryService_StreamTapConfigsServer) error
	DeltaTapConfigs(TapDiscoveryService_DeltaTapConfigsServer) error
	FetchTapConfigs(context.Context, *v2.DiscoveryRequest) (*v2.DiscoveryResponse, error)
}

func RegisterTapDiscoveryServiceServer(s *grpc.Server, srv TapDiscoveryServiceServer) {
	s.RegisterService(&_TapDiscoveryService_serviceDesc, srv)
}

func _TapDiscoveryService_StreamTapConfigs_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TapDiscoveryServiceServer).StreamTapConfigs(&tapDiscoveryServiceStreamTapConfigsServer{stream})
}

type TapDiscoveryService_StreamTapConfigsServer interface {
	Send(*v2.DiscoveryResponse) error
	Recv() (*v2.DiscoveryRequest, error)
	grpc.ServerStream
}

type tapDiscoveryServiceStreamTapConfigsServer struct {
	grpc.ServerStream
}

func (x *tapDiscoveryServiceStreamTapConfigsServer) Send(m *v2.DiscoveryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tapDiscoveryServiceStreamTapConfigsServer) Recv() (*v2.DiscoveryRequest, error) {
	m := new(v2.DiscoveryRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _TapDiscoveryService_DeltaTapConfigs_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(TapDiscoveryServiceServer).DeltaTapConfigs(&tapDiscoveryServiceDeltaTapConfigsServer{stream})
}

type TapDiscoveryService_DeltaTapConfigsServer interface {
	Send(*v2.DeltaDiscoveryResponse) error
	Recv() (*v2.DeltaDiscoveryRequest, error)
	grpc.ServerStream
}

type tapDiscoveryServiceDeltaTapConfigsServer struct {
	grpc.ServerStream
}

func (x *tapDiscoveryServiceDeltaTapConfigsServer) Send(m *v2.DeltaDiscoveryResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *tapDiscoveryServiceDeltaTapConfigsServer) Recv() (*v2.DeltaDiscoveryRequest, error) {
	m := new(v2.DeltaDiscoveryRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _TapDiscoveryService_FetchTapConfigs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(v2.DiscoveryRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TapDiscoveryServiceServer).FetchTapConfigs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/envoy.service.tap.v2alpha.TapDiscoveryService/FetchTapConfigs",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TapDiscoveryServiceServer).FetchTapConfigs(ctx, req.(*v2.DiscoveryRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _TapDiscoveryService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "envoy.service.tap.v2alpha.TapDiscoveryService",
	HandlerType: (*TapDiscoveryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "FetchTapConfigs",
			Handler:    _TapDiscoveryService_FetchTapConfigs_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "StreamTapConfigs",
			Handler:       _TapDiscoveryService_StreamTapConfigs_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "DeltaTapConfigs",
			Handler:       _TapDiscoveryService_DeltaTapConfigs_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "envoy/service/tap/v2alpha/tapds.proto",
}

func (m *TapResource) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TapResource) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		dAtA[i] = 0xa
		i++
		i = encodeVarintTapds(dAtA, i, uint64(len(m.Name)))
		i += copy(dAtA[i:], m.Name)
	}
	if m.Config != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintTapds(dAtA, i, uint64(m.Config.Size()))
		n1, err := m.Config.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintTapds(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *TapResource) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovTapds(uint64(l))
	}
	if m.Config != nil {
		l = m.Config.Size()
		n += 1 + l + sovTapds(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovTapds(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozTapds(x uint64) (n int) {
	return sovTapds(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *TapResource) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowTapds
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
			return fmt.Errorf("proto: TapResource: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TapResource: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTapds
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
				return ErrInvalidLengthTapds
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthTapds
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Config", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowTapds
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
				return ErrInvalidLengthTapds
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthTapds
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Config == nil {
				m.Config = &TapConfig{}
			}
			if err := m.Config.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipTapds(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthTapds
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthTapds
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			m.XXX_unrecognized = append(m.XXX_unrecognized, dAtA[iNdEx:iNdEx+skippy]...)
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipTapds(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowTapds
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
					return 0, ErrIntOverflowTapds
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
					return 0, ErrIntOverflowTapds
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
				return 0, ErrInvalidLengthTapds
			}
			iNdEx += length
			if iNdEx < 0 {
				return 0, ErrInvalidLengthTapds
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowTapds
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
				next, err := skipTapds(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
				if iNdEx < 0 {
					return 0, ErrInvalidLengthTapds
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
	ErrInvalidLengthTapds = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowTapds   = fmt.Errorf("proto: integer overflow")
)
