// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: envoy/api/v2/endpoint/endpoint.proto

package endpoint

import proto "github.com/gogo/protobuf/proto"
import fmt "fmt"
import math "math"
import core "github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
import _ "github.com/gogo/protobuf/gogoproto"
import types "github.com/gogo/protobuf/types"
import _ "github.com/lyft/protoc-gen-validate/validate"

import bytes "bytes"

import io "io"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion2 // please upgrade the proto package

// Upstream host identifier.
type Endpoint struct {
	// The upstream host address.
	//
	// .. attention::
	//
	//   The form of host address depends on the given cluster type. For STATIC or EDS,
	//   it is expected to be a direct IP address (or something resolvable by the
	//   specified :ref:`resolver <envoy_api_field_core.SocketAddress.resolver_name>`
	//   in the Address). For LOGICAL or STRICT DNS, it is expected to be hostname,
	//   and will be resolved via DNS.
	Address *core.Address `protobuf:"bytes,1,opt,name=address" json:"address,omitempty"`
	// The optional health check configuration is used as configuration for the
	// health checker to contact the health checked host.
	//
	// .. attention::
	//
	//   This takes into effect only for upstream clusters with
	//   :ref:`active health checking <arch_overview_health_checking>` enabled.
	HealthCheckConfig    *Endpoint_HealthCheckConfig `protobuf:"bytes,2,opt,name=health_check_config,json=healthCheckConfig" json:"health_check_config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                    `json:"-"`
	XXX_unrecognized     []byte                      `json:"-"`
	XXX_sizecache        int32                       `json:"-"`
}

func (m *Endpoint) Reset()         { *m = Endpoint{} }
func (m *Endpoint) String() string { return proto.CompactTextString(m) }
func (*Endpoint) ProtoMessage()    {}
func (*Endpoint) Descriptor() ([]byte, []int) {
	return fileDescriptor_endpoint_700e84888719f639, []int{0}
}
func (m *Endpoint) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Endpoint) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Endpoint.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Endpoint) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Endpoint.Merge(dst, src)
}
func (m *Endpoint) XXX_Size() int {
	return m.Size()
}
func (m *Endpoint) XXX_DiscardUnknown() {
	xxx_messageInfo_Endpoint.DiscardUnknown(m)
}

var xxx_messageInfo_Endpoint proto.InternalMessageInfo

func (m *Endpoint) GetAddress() *core.Address {
	if m != nil {
		return m.Address
	}
	return nil
}

func (m *Endpoint) GetHealthCheckConfig() *Endpoint_HealthCheckConfig {
	if m != nil {
		return m.HealthCheckConfig
	}
	return nil
}

// The optional health check configuration.
type Endpoint_HealthCheckConfig struct {
	// Optional alternative health check port value.
	//
	// By default the health check address port of an upstream host is the same
	// as the host's serving address port. This provides an alternative health
	// check port. Setting this with a non-zero value allows an upstream host
	// to have different health check address port.
	PortValue            uint32   `protobuf:"varint,1,opt,name=port_value,json=portValue,proto3" json:"port_value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Endpoint_HealthCheckConfig) Reset()         { *m = Endpoint_HealthCheckConfig{} }
func (m *Endpoint_HealthCheckConfig) String() string { return proto.CompactTextString(m) }
func (*Endpoint_HealthCheckConfig) ProtoMessage()    {}
func (*Endpoint_HealthCheckConfig) Descriptor() ([]byte, []int) {
	return fileDescriptor_endpoint_700e84888719f639, []int{0, 0}
}
func (m *Endpoint_HealthCheckConfig) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *Endpoint_HealthCheckConfig) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_Endpoint_HealthCheckConfig.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *Endpoint_HealthCheckConfig) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Endpoint_HealthCheckConfig.Merge(dst, src)
}
func (m *Endpoint_HealthCheckConfig) XXX_Size() int {
	return m.Size()
}
func (m *Endpoint_HealthCheckConfig) XXX_DiscardUnknown() {
	xxx_messageInfo_Endpoint_HealthCheckConfig.DiscardUnknown(m)
}

var xxx_messageInfo_Endpoint_HealthCheckConfig proto.InternalMessageInfo

func (m *Endpoint_HealthCheckConfig) GetPortValue() uint32 {
	if m != nil {
		return m.PortValue
	}
	return 0
}

// An Endpoint that Envoy can route traffic to.
type LbEndpoint struct {
	// Upstream host identifier
	Endpoint *Endpoint `protobuf:"bytes,1,opt,name=endpoint" json:"endpoint,omitempty"`
	// Optional health status when known and supplied by EDS server.
	HealthStatus core.HealthStatus `protobuf:"varint,2,opt,name=health_status,json=healthStatus,proto3,enum=envoy.api.v2.core.HealthStatus" json:"health_status,omitempty"`
	// The endpoint metadata specifies values that may be used by the load
	// balancer to select endpoints in a cluster for a given request. The filter
	// name should be specified as *envoy.lb*. An example boolean key-value pair
	// is *canary*, providing the optional canary status of the upstream host.
	// This may be matched against in a route's ForwardAction metadata_match field
	// to subset the endpoints considered in cluster load balancing.
	Metadata *core.Metadata `protobuf:"bytes,3,opt,name=metadata" json:"metadata,omitempty"`
	// The optional load balancing weight of the upstream host, in the range 1 -
	// 128. Envoy uses the load balancing weight in some of the built in load
	// balancers. The load balancing weight for an endpoint is divided by the sum
	// of the weights of all endpoints in the endpoint's locality to produce a
	// percentage of traffic for the endpoint. This percentage is then further
	// weighted by the endpoint's locality's load balancing weight from
	// LocalityLbEndpoints. If unspecified, each host is presumed to have equal
	// weight in a locality.
	//
	// .. attention::
	//
	//   The limit of 128 is somewhat arbitrary, but is applied due to performance
	//   concerns with the current implementation and can be removed when
	//   `this issue <https://github.com/envoyproxy/envoy/issues/1285>`_ is fixed.
	LoadBalancingWeight  *types.UInt32Value `protobuf:"bytes,4,opt,name=load_balancing_weight,json=loadBalancingWeight" json:"load_balancing_weight,omitempty"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *LbEndpoint) Reset()         { *m = LbEndpoint{} }
func (m *LbEndpoint) String() string { return proto.CompactTextString(m) }
func (*LbEndpoint) ProtoMessage()    {}
func (*LbEndpoint) Descriptor() ([]byte, []int) {
	return fileDescriptor_endpoint_700e84888719f639, []int{1}
}
func (m *LbEndpoint) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LbEndpoint) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LbEndpoint.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *LbEndpoint) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LbEndpoint.Merge(dst, src)
}
func (m *LbEndpoint) XXX_Size() int {
	return m.Size()
}
func (m *LbEndpoint) XXX_DiscardUnknown() {
	xxx_messageInfo_LbEndpoint.DiscardUnknown(m)
}

var xxx_messageInfo_LbEndpoint proto.InternalMessageInfo

func (m *LbEndpoint) GetEndpoint() *Endpoint {
	if m != nil {
		return m.Endpoint
	}
	return nil
}

func (m *LbEndpoint) GetHealthStatus() core.HealthStatus {
	if m != nil {
		return m.HealthStatus
	}
	return core.HealthStatus_UNKNOWN
}

func (m *LbEndpoint) GetMetadata() *core.Metadata {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *LbEndpoint) GetLoadBalancingWeight() *types.UInt32Value {
	if m != nil {
		return m.LoadBalancingWeight
	}
	return nil
}

// A group of endpoints belonging to a Locality.
// One can have multiple LocalityLbEndpoints for a locality, but this is
// generally only done if the different groups need to have different load
// balancing weights or different priorities.
type LocalityLbEndpoints struct {
	// Identifies location of where the upstream hosts run.
	Locality *core.Locality `protobuf:"bytes,1,opt,name=locality" json:"locality,omitempty"`
	// The group of endpoints belonging to the locality specified.
	LbEndpoints []LbEndpoint `protobuf:"bytes,2,rep,name=lb_endpoints,json=lbEndpoints" json:"lb_endpoints"`
	// Optional: Per priority/region/zone/sub_zone weight - range 1-128. The load
	// balancing weight for a locality is divided by the sum of the weights of all
	// localities  at the same priority level to produce the effective percentage
	// of traffic for the locality.
	//
	// Locality weights are only considered when :ref:`locality weighted load
	// balancing <arch_overview_load_balancing_locality_weighted_lb>` is
	// configured. These weights are ignored otherwise. If no weights are
	// specificed when locality weighted load balancing is enabled, the cluster is
	// assumed to have a weight of 1.
	//
	// .. attention::
	//
	//   The limit of 128 is somewhat arbitrary, but is applied due to performance
	//   concerns with the current implementation and can be removed when
	//   `this issue <https://github.com/envoyproxy/envoy/issues/1285>`_ is fixed.
	LoadBalancingWeight *types.UInt32Value `protobuf:"bytes,3,opt,name=load_balancing_weight,json=loadBalancingWeight" json:"load_balancing_weight,omitempty"`
	// Optional: the priority for this LocalityLbEndpoints. If unspecified this will
	// default to the highest priority (0).
	//
	// Under usual circumstances, Envoy will only select endpoints for the highest
	// priority (0). In the event all endpoints for a particular priority are
	// unavailable/unhealthy, Envoy will fail over to selecting endpoints for the
	// next highest priority group.
	//
	// Priorities should range from 0 (highest) to N (lowest) without skipping.
	Priority             uint32   `protobuf:"varint,5,opt,name=priority,proto3" json:"priority,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *LocalityLbEndpoints) Reset()         { *m = LocalityLbEndpoints{} }
func (m *LocalityLbEndpoints) String() string { return proto.CompactTextString(m) }
func (*LocalityLbEndpoints) ProtoMessage()    {}
func (*LocalityLbEndpoints) Descriptor() ([]byte, []int) {
	return fileDescriptor_endpoint_700e84888719f639, []int{2}
}
func (m *LocalityLbEndpoints) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *LocalityLbEndpoints) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_LocalityLbEndpoints.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalTo(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (dst *LocalityLbEndpoints) XXX_Merge(src proto.Message) {
	xxx_messageInfo_LocalityLbEndpoints.Merge(dst, src)
}
func (m *LocalityLbEndpoints) XXX_Size() int {
	return m.Size()
}
func (m *LocalityLbEndpoints) XXX_DiscardUnknown() {
	xxx_messageInfo_LocalityLbEndpoints.DiscardUnknown(m)
}

var xxx_messageInfo_LocalityLbEndpoints proto.InternalMessageInfo

func (m *LocalityLbEndpoints) GetLocality() *core.Locality {
	if m != nil {
		return m.Locality
	}
	return nil
}

func (m *LocalityLbEndpoints) GetLbEndpoints() []LbEndpoint {
	if m != nil {
		return m.LbEndpoints
	}
	return nil
}

func (m *LocalityLbEndpoints) GetLoadBalancingWeight() *types.UInt32Value {
	if m != nil {
		return m.LoadBalancingWeight
	}
	return nil
}

func (m *LocalityLbEndpoints) GetPriority() uint32 {
	if m != nil {
		return m.Priority
	}
	return 0
}

func init() {
	proto.RegisterType((*Endpoint)(nil), "envoy.api.v2.endpoint.Endpoint")
	proto.RegisterType((*Endpoint_HealthCheckConfig)(nil), "envoy.api.v2.endpoint.Endpoint.HealthCheckConfig")
	proto.RegisterType((*LbEndpoint)(nil), "envoy.api.v2.endpoint.LbEndpoint")
	proto.RegisterType((*LocalityLbEndpoints)(nil), "envoy.api.v2.endpoint.LocalityLbEndpoints")
}
func (this *Endpoint) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Endpoint)
	if !ok {
		that2, ok := that.(Endpoint)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !this.Address.Equal(that1.Address) {
		return false
	}
	if !this.HealthCheckConfig.Equal(that1.HealthCheckConfig) {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *Endpoint_HealthCheckConfig) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*Endpoint_HealthCheckConfig)
	if !ok {
		that2, ok := that.(Endpoint_HealthCheckConfig)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.PortValue != that1.PortValue {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *LbEndpoint) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*LbEndpoint)
	if !ok {
		that2, ok := that.(LbEndpoint)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !this.Endpoint.Equal(that1.Endpoint) {
		return false
	}
	if this.HealthStatus != that1.HealthStatus {
		return false
	}
	if !this.Metadata.Equal(that1.Metadata) {
		return false
	}
	if !this.LoadBalancingWeight.Equal(that1.LoadBalancingWeight) {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (this *LocalityLbEndpoints) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*LocalityLbEndpoints)
	if !ok {
		that2, ok := that.(LocalityLbEndpoints)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !this.Locality.Equal(that1.Locality) {
		return false
	}
	if len(this.LbEndpoints) != len(that1.LbEndpoints) {
		return false
	}
	for i := range this.LbEndpoints {
		if !this.LbEndpoints[i].Equal(&that1.LbEndpoints[i]) {
			return false
		}
	}
	if !this.LoadBalancingWeight.Equal(that1.LoadBalancingWeight) {
		return false
	}
	if this.Priority != that1.Priority {
		return false
	}
	if !bytes.Equal(this.XXX_unrecognized, that1.XXX_unrecognized) {
		return false
	}
	return true
}
func (m *Endpoint) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Endpoint) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Address != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.Address.Size()))
		n1, err := m.Address.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n1
	}
	if m.HealthCheckConfig != nil {
		dAtA[i] = 0x12
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.HealthCheckConfig.Size()))
		n2, err := m.HealthCheckConfig.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n2
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *Endpoint_HealthCheckConfig) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *Endpoint_HealthCheckConfig) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.PortValue != 0 {
		dAtA[i] = 0x8
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.PortValue))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *LbEndpoint) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LbEndpoint) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Endpoint != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.Endpoint.Size()))
		n3, err := m.Endpoint.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n3
	}
	if m.HealthStatus != 0 {
		dAtA[i] = 0x10
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.HealthStatus))
	}
	if m.Metadata != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.Metadata.Size()))
		n4, err := m.Metadata.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n4
	}
	if m.LoadBalancingWeight != nil {
		dAtA[i] = 0x22
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.LoadBalancingWeight.Size()))
		n5, err := m.LoadBalancingWeight.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n5
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func (m *LocalityLbEndpoints) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalTo(dAtA)
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *LocalityLbEndpoints) MarshalTo(dAtA []byte) (int, error) {
	var i int
	_ = i
	var l int
	_ = l
	if m.Locality != nil {
		dAtA[i] = 0xa
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.Locality.Size()))
		n6, err := m.Locality.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n6
	}
	if len(m.LbEndpoints) > 0 {
		for _, msg := range m.LbEndpoints {
			dAtA[i] = 0x12
			i++
			i = encodeVarintEndpoint(dAtA, i, uint64(msg.Size()))
			n, err := msg.MarshalTo(dAtA[i:])
			if err != nil {
				return 0, err
			}
			i += n
		}
	}
	if m.LoadBalancingWeight != nil {
		dAtA[i] = 0x1a
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.LoadBalancingWeight.Size()))
		n7, err := m.LoadBalancingWeight.MarshalTo(dAtA[i:])
		if err != nil {
			return 0, err
		}
		i += n7
	}
	if m.Priority != 0 {
		dAtA[i] = 0x28
		i++
		i = encodeVarintEndpoint(dAtA, i, uint64(m.Priority))
	}
	if m.XXX_unrecognized != nil {
		i += copy(dAtA[i:], m.XXX_unrecognized)
	}
	return i, nil
}

func encodeVarintEndpoint(dAtA []byte, offset int, v uint64) int {
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return offset + 1
}
func (m *Endpoint) Size() (n int) {
	var l int
	_ = l
	if m.Address != nil {
		l = m.Address.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.HealthCheckConfig != nil {
		l = m.HealthCheckConfig.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *Endpoint_HealthCheckConfig) Size() (n int) {
	var l int
	_ = l
	if m.PortValue != 0 {
		n += 1 + sovEndpoint(uint64(m.PortValue))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *LbEndpoint) Size() (n int) {
	var l int
	_ = l
	if m.Endpoint != nil {
		l = m.Endpoint.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.HealthStatus != 0 {
		n += 1 + sovEndpoint(uint64(m.HealthStatus))
	}
	if m.Metadata != nil {
		l = m.Metadata.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.LoadBalancingWeight != nil {
		l = m.LoadBalancingWeight.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func (m *LocalityLbEndpoints) Size() (n int) {
	var l int
	_ = l
	if m.Locality != nil {
		l = m.Locality.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if len(m.LbEndpoints) > 0 {
		for _, e := range m.LbEndpoints {
			l = e.Size()
			n += 1 + l + sovEndpoint(uint64(l))
		}
	}
	if m.LoadBalancingWeight != nil {
		l = m.LoadBalancingWeight.Size()
		n += 1 + l + sovEndpoint(uint64(l))
	}
	if m.Priority != 0 {
		n += 1 + sovEndpoint(uint64(m.Priority))
	}
	if m.XXX_unrecognized != nil {
		n += len(m.XXX_unrecognized)
	}
	return n
}

func sovEndpoint(x uint64) (n int) {
	for {
		n++
		x >>= 7
		if x == 0 {
			break
		}
	}
	return n
}
func sozEndpoint(x uint64) (n int) {
	return sovEndpoint(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *Endpoint) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEndpoint
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: Endpoint: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: Endpoint: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Address", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Address == nil {
				m.Address = &core.Address{}
			}
			if err := m.Address.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field HealthCheckConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.HealthCheckConfig == nil {
				m.HealthCheckConfig = &Endpoint_HealthCheckConfig{}
			}
			if err := m.HealthCheckConfig.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipEndpoint(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEndpoint
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
func (m *Endpoint_HealthCheckConfig) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEndpoint
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: HealthCheckConfig: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: HealthCheckConfig: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field PortValue", wireType)
			}
			m.PortValue = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.PortValue |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipEndpoint(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEndpoint
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
func (m *LbEndpoint) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEndpoint
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LbEndpoint: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LbEndpoint: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Endpoint", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Endpoint == nil {
				m.Endpoint = &Endpoint{}
			}
			if err := m.Endpoint.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field HealthStatus", wireType)
			}
			m.HealthStatus = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.HealthStatus |= (core.HealthStatus(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Metadata", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Metadata == nil {
				m.Metadata = &core.Metadata{}
			}
			if err := m.Metadata.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LoadBalancingWeight", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.LoadBalancingWeight == nil {
				m.LoadBalancingWeight = &types.UInt32Value{}
			}
			if err := m.LoadBalancingWeight.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipEndpoint(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEndpoint
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
func (m *LocalityLbEndpoints) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowEndpoint
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: LocalityLbEndpoints: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: LocalityLbEndpoints: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Locality", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.Locality == nil {
				m.Locality = &core.Locality{}
			}
			if err := m.Locality.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LbEndpoints", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.LbEndpoints = append(m.LbEndpoints, LbEndpoint{})
			if err := m.LbEndpoints[len(m.LbEndpoints)-1].Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 3:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field LoadBalancingWeight", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthEndpoint
			}
			postIndex := iNdEx + msglen
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if m.LoadBalancingWeight == nil {
				m.LoadBalancingWeight = &types.UInt32Value{}
			}
			if err := m.LoadBalancingWeight.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field Priority", wireType)
			}
			m.Priority = 0
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowEndpoint
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				m.Priority |= (uint32(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
		default:
			iNdEx = preIndex
			skippy, err := skipEndpoint(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthEndpoint
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
func skipEndpoint(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowEndpoint
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
					return 0, ErrIntOverflowEndpoint
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
					return 0, ErrIntOverflowEndpoint
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
			iNdEx += length
			if length < 0 {
				return 0, ErrInvalidLengthEndpoint
			}
			return iNdEx, nil
		case 3:
			for {
				var innerWire uint64
				var start int = iNdEx
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return 0, ErrIntOverflowEndpoint
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
				next, err := skipEndpoint(dAtA[start:])
				if err != nil {
					return 0, err
				}
				iNdEx = start + next
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
	ErrInvalidLengthEndpoint = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowEndpoint   = fmt.Errorf("proto: integer overflow")
)

func init() {
	proto.RegisterFile("envoy/api/v2/endpoint/endpoint.proto", fileDescriptor_endpoint_700e84888719f639)
}

var fileDescriptor_endpoint_700e84888719f639 = []byte{
	// 532 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x52, 0x41, 0x6f, 0xd3, 0x30,
	0x14, 0xc6, 0x4b, 0xbb, 0x15, 0xb7, 0x43, 0x5a, 0xca, 0x44, 0x54, 0xa6, 0x16, 0xaa, 0x09, 0x55,
	0x3d, 0x38, 0xa2, 0x43, 0xe2, 0xc0, 0x01, 0xd1, 0x81, 0x04, 0x68, 0x5c, 0x8c, 0x00, 0x89, 0x03,
	0x91, 0x93, 0x78, 0x49, 0x84, 0x89, 0xa3, 0xc4, 0xcd, 0xb4, 0xdb, 0x7e, 0x0b, 0xa7, 0xfd, 0x06,
	0x4e, 0x1c, 0x77, 0xe4, 0x17, 0x20, 0x54, 0x71, 0xe1, 0x57, 0x0c, 0xd9, 0xb1, 0xb3, 0x6e, 0xed,
	0xc4, 0x85, 0xdb, 0xb3, 0xdf, 0xf7, 0xbd, 0xf7, 0x7d, 0x9f, 0x1e, 0xdc, 0xa5, 0x69, 0xc9, 0x8f,
	0x5d, 0x92, 0x25, 0x6e, 0x39, 0x71, 0x69, 0x1a, 0x66, 0x3c, 0x49, 0x45, 0x5d, 0xa0, 0x2c, 0xe7,
	0x82, 0xdb, 0xdb, 0x0a, 0x85, 0x48, 0x96, 0xa0, 0x72, 0x82, 0x4c, 0xb3, 0x37, 0xb8, 0x44, 0x0e,
	0x78, 0x4e, 0x5d, 0x12, 0x86, 0x39, 0x2d, 0x8a, 0x8a, 0xd7, 0xdb, 0x59, 0x06, 0xf8, 0xa4, 0xa0,
	0xba, 0xbb, 0xbb, 0xdc, 0x8d, 0x29, 0x61, 0x22, 0xf6, 0x82, 0x98, 0x06, 0x9f, 0x35, 0xaa, 0x1f,
	0x71, 0x1e, 0x31, 0xea, 0xaa, 0x97, 0x3f, 0x3b, 0x74, 0x8f, 0x72, 0x92, 0x65, 0x34, 0x37, 0x3b,
	0xee, 0x94, 0x84, 0x25, 0x21, 0x11, 0xd4, 0x35, 0x85, 0x6e, 0xdc, 0x8e, 0x78, 0xc4, 0x55, 0xe9,
	0xca, 0xaa, 0xfa, 0x1d, 0xfe, 0x06, 0xb0, 0xf5, 0x42, 0x1b, 0xb0, 0x1f, 0xc1, 0x0d, 0x2d, 0xd8,
	0x01, 0xf7, 0xc0, 0xa8, 0x3d, 0xe9, 0xa1, 0x4b, 0x4e, 0xa5, 0x26, 0xf4, 0xac, 0x42, 0x60, 0x03,
	0xb5, 0x09, 0xec, 0x2e, 0xea, 0xf4, 0x02, 0x9e, 0x1e, 0x26, 0x91, 0xb3, 0xa6, 0x26, 0x3c, 0x44,
	0x2b, 0xb3, 0x42, 0x66, 0x27, 0x7a, 0xa9, 0xa8, 0xfb, 0x92, 0xb9, 0xaf, 0x88, 0x78, 0x2b, 0xbe,
	0xfa, 0xd5, 0x7b, 0x0a, 0xb7, 0x96, 0x70, 0xf6, 0x18, 0xc2, 0x8c, 0xe7, 0xc2, 0x2b, 0x09, 0x9b,
	0x51, 0x25, 0x78, 0x73, 0xda, 0xfe, 0xf6, 0xe7, 0xbb, 0xb5, 0x3e, 0x6e, 0x38, 0xe7, 0xe7, 0x16,
	0xbe, 0x29, 0xdb, 0xef, 0x65, 0x77, 0x78, 0xba, 0x06, 0xe1, 0x81, 0x5f, 0x1b, 0x7d, 0x02, 0x5b,
	0x46, 0x89, 0x76, 0x3a, 0xf8, 0x87, 0x4e, 0x5c, 0x13, 0xec, 0xe7, 0x70, 0x53, 0xfb, 0x2d, 0x04,
	0x11, 0xb3, 0x42, 0x39, 0xbd, 0x75, 0x75, 0x82, 0xca, 0xaa, 0x12, 0xfd, 0x56, 0xc1, 0x70, 0x27,
	0x5e, 0x78, 0xd9, 0x8f, 0x61, 0xeb, 0x0b, 0x15, 0x24, 0x24, 0x82, 0x38, 0x96, 0x92, 0x70, 0x77,
	0xc5, 0x80, 0x37, 0x1a, 0x82, 0x6b, 0xb0, 0xfd, 0x09, 0x6e, 0x33, 0x4e, 0x42, 0xcf, 0x27, 0x8c,
	0xa4, 0x41, 0x92, 0x46, 0xde, 0x11, 0x4d, 0xa2, 0x58, 0x38, 0x0d, 0x35, 0x65, 0x07, 0x55, 0x07,
	0x82, 0xcc, 0x81, 0xa0, 0x77, 0xaf, 0x52, 0xb1, 0x37, 0x51, 0x39, 0x4c, 0x3b, 0x32, 0x9f, 0x8d,
	0x71, 0xd3, 0x39, 0x01, 0x23, 0x80, 0xbb, 0x72, 0xd0, 0xd4, 0xcc, 0xf9, 0xa0, 0xc6, 0x0c, 0xbf,
	0xae, 0xc1, 0xee, 0x01, 0x0f, 0x08, 0x4b, 0xc4, 0xf1, 0x45, 0x64, 0x4a, 0x30, 0xd3, 0xdf, 0x3a,
	0xb3, 0x55, 0x82, 0x0d, 0x13, 0xd7, 0x60, 0xfb, 0x35, 0xec, 0x30, 0xdf, 0x33, 0xf1, 0xc9, 0xb8,
	0xac, 0x51, 0x7b, 0x72, 0xff, 0x9a, 0xc0, 0x2f, 0x56, 0x4e, 0x1b, 0x67, 0x3f, 0x07, 0x37, 0x70,
	0x9b, 0x2d, 0x88, 0xb8, 0xd6, 0xbc, 0xf5, 0x5f, 0xcc, 0xdb, 0x0f, 0x60, 0x2b, 0xcb, 0x13, 0x9e,
	0x4b, 0x93, 0x4d, 0x75, 0x51, 0x50, 0x92, 0x9a, 0x63, 0xcb, 0x39, 0x01, 0xb8, 0xee, 0x4d, 0x7b,
	0xa7, 0xf3, 0x3e, 0x38, 0x9b, 0xf7, 0xc1, 0x8f, 0x79, 0x1f, 0xfc, 0x9a, 0xf7, 0xc1, 0xc7, 0xfa,
	0x3e, 0xfc, 0x75, 0xb5, 0x7c, 0xef, 0x6f, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc8, 0xe0, 0x0f, 0x4c,
	0x4c, 0x04, 0x00, 0x00,
}
