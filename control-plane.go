package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoyhttpcsrf "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/csrf/v3"
	envoyhttpoauth2 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoyauth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	secretv3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	envoytypematcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	envoytypev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	xds "github.com/envoyproxy/go-control-plane/pkg/server/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/wrappers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
)

const (
	selfSignedCertificate = `
-----BEGIN CERTIFICATE-----
MIIBszCCAVqgAwIBAgIRAIYTwHQIHCrnyz+MN35B3KUwCgYIKoZIzj0EAwIwITEf
MB0GA1UEAxMWc2VsZi1zaWduZWQtbGVhZi5sb2NhbDAeFw0yMjA4MDgxNTQ3MDla
Fw0yMjA4MDkxNTQ3MDlaMCExHzAdBgNVBAMTFnNlbGYtc2lnbmVkLWxlYWYubG9j
YWwwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARYdXUqZif5oijKZnte3v0bYIOX
kVnsrJXNUC/f/20R6o6X2OzdjrW3ha+cKzKg+5zgS5aXjO4DMKgLbn/siphbo3Mw
cTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MB0GA1UdDgQWBBR1r8D8qWdT6lYrzBGYcchBylt81zAhBgNVHREEGjAYghZzZWxm
LXNpZ25lZC1sZWFmLmxvY2FsMAoGCCqGSM49BAMCA0cAMEQCICT/gh4P8JJ8QJw4
7L1kj6/4EBG8lLFb1qKSubiB8TBRAiArh1SGHJ3HP6PF2m5T/9FUl2Ux8s/ihhG+
6u0Bgj/6Nw==
-----END CERTIFICATE-----
`
	selfSignedKey = `
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM7XmxwMVsD5aXj7HsgBT+RMTflRFvao4+ZHHiPE+d66oAoGCCqGSM49
AwEHoUQDQgAEWHV1KmYn+aIoymZ7Xt79G2CDl5FZ7KyVzVAv3/9tEeqOl9js3Y61
t4WvnCsyoPuc4EuWl4zuAzCoC25/7IqYWw==
-----END EC PRIVATE KEY-----
`
	envoyNodeId = "envoy"
)
const (
	grpcKeepaliveTime        = 30 * time.Second
	grpcKeepaliveTimeout     = 5 * time.Second
	grpcKeepaliveMinTime     = 30 * time.Second
	grpcMaxConcurrentStreams = 1000000
)

var (
	//adsConfig = &core.ConfigSource{
	//	ResourceApiVersion: core.ApiVersion_V3,
	//	ConfigSourceSpecifier: &core.ConfigSource_Ads{
	//		Ads: &core.AggregatedConfigSource{},
	//	},
	//}
	sdsConfig = &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				TransportApiVersion: core.ApiVersion_V3,
				ApiType:             core.ApiConfigSource_GRPC,
				GrpcServices: []*core.GrpcService{
					{
						TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
							EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "sds"},
						},
					},
				},
			},
		},
	}
	secretsConfig = sdsConfig
)

type snapshotManager struct {
	cache     cache.SnapshotCache
	resources []cache.ResourceSnapshot
	index     int
	mu        sync.Mutex
}

func (w *snapshotManager) updateVersion() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.resources) == 0 {
		return nil
	}
	w.index = (w.index + 1) % len(w.resources)
	snapshot := w.resources[w.index]
	index := w.index
	log.Println("setting snapshot to index", index, "version", snapshot.GetVersion(resource.ListenerType))
	return w.cache.SetSnapshot(context.Background(), envoyNodeId, snapshot)
}

func (w *snapshotManager) initVersion() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.resources) == 0 {
		return nil
	}
	snapshot := w.resources[w.index]
	index := w.index
	log.Println("setting snapshot to index", index, "version", snapshot.GetVersion(resource.ListenerType))
	return w.cache.SetSnapshot(context.Background(), envoyNodeId, snapshot)
}

type noHash struct{}

func (noHash) ID(_ *core.Node) string {
	return envoyNodeId
}

func main() {

	snapshotCache := cache.NewSnapshotCache(false, noHash{}, nil)
	sm := getSnapshotManager(snapshotCache)
	if err := sm.initVersion(); err != nil {
		log.Fatal("init_version: ", err.Error())
	}
	grpcServer := getGrpcServer(snapshotCache)

	//tcpListener, listenErr := net.Listen("tcp", ":7001")
	tcpListener, listenErr := net.Listen("tcp", ":18000")
	if listenErr != nil {
		log.Fatal("net.listen: ", listenErr.Error())
	}

	log.Println("listening on :18000")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{}, 1)

	go func(done chan struct{}, sm *snapshotManager) {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			select {
			case <-done:
				return
			default:
				break
			}
			if scanner.Scan() {
				if err := sm.updateVersion(); err != nil {
					log.Println("update-version: ", err.Error())
				}
			}
		}
	}(done, sm)

	go func(grpcServer *grpc.Server) {
		if err := grpcServer.Serve(tcpListener); err != nil {
			if err != grpc.ErrServerStopped {
				log.Println("grpc.serve: ", err.Error())
			}
		}
	}(grpcServer)

loop:
	for {
		select {
		case <-signals:
			break loop
		}
	}

	log.Println("exiting")

	close(done)
	grpcServer.Stop()
	if err := tcpListener.Close(); err != nil {
		log.Println("listener.close: ", err.Error())
	}

}

func getSnapshotManager(snapshotCache cache.SnapshotCache) *snapshotManager {
	resourcesWithoutOAuth2 := getResourcesWithoutOauth2()

	resourcesWithOAuth2 := getResourcesWithOauth2()

	snapshotWithoutOAuth2, snapshotWithoutOAuth2Err := cache.NewSnapshot("no-oauth2", resourcesWithoutOAuth2)
	if snapshotWithoutOAuth2Err != nil {
		log.Fatal("cache.NewSnapshot: ", snapshotWithoutOAuth2Err.Error())
	}
	snapshotWithOAuth2, snapshotWithOAuth2Err := cache.NewSnapshot("oauth2", resourcesWithOAuth2)
	if snapshotWithOAuth2Err != nil {
		log.Fatal("cache.NewSnapshot: ", snapshotWithOAuth2Err.Error())
	}
	sm := &snapshotManager{
		cache:     snapshotCache,
		resources: []cache.ResourceSnapshot{snapshotWithoutOAuth2, snapshotWithOAuth2},
	}
	return sm
}

func getResourcesWithoutOauth2() map[resource.Type][]types.Resource {
	return map[resource.Type][]types.Resource{
		resource.ClusterType:  {makeCluster("upstream_cluster")},
		resource.ListenerType: {makeHTTPListener()},
		resource.SecretType:   makeSecrets(),
	}
}
func getResourcesWithOauth2() map[resource.Type][]types.Resource {
	return map[resource.Type][]types.Resource{
		resource.ClusterType:  {makeCluster("upstream_cluster"), makeCluster("oauth2_cluster")},
		resource.ListenerType: {makeHTTPListenerWithOAuth2()},
		resource.SecretType:   append(makeSecrets(), makeOAuth2Secrets()...),
	}
}

func getGrpcServer(snapshotCache cache.SnapshotCache) *grpc.Server {
	server := xds.NewServer(context.Background(), snapshotCache, nil)
	// kp, kpErr := tls.X509KeyPair([]byte(selfSignedCertificate), []byte(selfSignedKey))
	// if kpErr != nil {
	// 	log.Fatal("tls.X509KeyPair: ", kpErr.Error())
	// }
	// transportCredentials := credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{kp}})
	//grpcServer := grpc.NewServer(grpc.Creds(transportCredentials))

	var grpcOptions []grpc.ServerOption
	grpcOptions = append(grpcOptions,
		grpc.MaxConcurrentStreams(grpcMaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    grpcKeepaliveTime,
			Timeout: grpcKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinTime,
			PermitWithoutStream: true,
		}),
	)
	grpcServer := grpc.NewServer(grpcOptions...)
	discovery.RegisterAggregatedDiscoveryServiceServer(grpcServer, server)
	secretv3.RegisterSecretDiscoveryServiceServer(grpcServer, server)
	return grpcServer
}

func makeCluster(clusterName string) *cluster.Cluster {

	tlsContext := &envoyauth.UpstreamTlsContext{
		CommonTlsContext: &envoyauth.CommonTlsContext{
			TlsParams: &envoyauth.TlsParameters{
				TlsMinimumProtocolVersion: envoyauth.TlsParameters_TLSv1_2,
			},
			AlpnProtocols: []string{"h2", "http/1.1"},
			ValidationContextType: &envoyauth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &envoyauth.SdsSecretConfig{
					Name:      "cluster_validation_context",
					SdsConfig: secretsConfig,
				},
			},
		},
	}

	tlsContextTypedConfig, tlsContextErr := anypb.New(tlsContext)
	if tlsContextErr != nil {
		panic(fmt.Errorf("anypb.New(tlsContext, %v)", tlsContextErr))
	}

	transportSocket := &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tlsContextTypedConfig,
		},
	}

	cluster := &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(30 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_LEAST_REQUEST,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: clusterName,
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HealthStatus: core.HealthStatus_HEALTHY,
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										Protocol: core.SocketAddress_TCP,
										Address:  "127.0.0.1",
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: 8443,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
		DnsLookupFamily:               cluster.Cluster_V4_ONLY,
		TransportSocket:               transportSocket,
		OutlierDetection:              &cluster.OutlierDetection{},
		CircuitBreakers:               &cluster.CircuitBreakers{},
		PerConnectionBufferLimitBytes: &wrappers.UInt32Value{Value: 32768},
		TypedExtensionProtocolOptions: make(map[string]*anypb.Any, 1),
	}

	httpProtocolOptions := &envoy_extensions_upstreams_http_v3.HttpProtocolOptions{
		CommonHttpProtocolOptions: &core.HttpProtocolOptions{
			HeadersWithUnderscoresAction: core.HttpProtocolOptions_REJECT_REQUEST,
		},
		UpstreamHttpProtocolOptions: &core.UpstreamHttpProtocolOptions{},
		UpstreamProtocolOptions: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &envoy_extensions_upstreams_http_v3.HttpProtocolOptions_ExplicitHttpConfig_HttpProtocolOptions{},
			},
		},
	}
	protocolOptionsConfig, httpProtocolOptionsErr := anypb.New(httpProtocolOptions)
	if httpProtocolOptionsErr != nil {
		panic(fmt.Errorf("anypb.New(httpProtocolOptions, %v)", httpProtocolOptionsErr))
	}
	cluster.TypedExtensionProtocolOptions["envoy.extensions.upstreams.http.v3.HttpProtocolOptions"] = protocolOptionsConfig
	return cluster
}

func makeHTTPListener() *listener.Listener {

	routerConfig, routerConfigErr := anypb.New(&router.Router{})
	if routerConfigErr != nil {
		panic(fmt.Errorf("anypb.New(router.Router, %v)", routerConfigErr))
	}

	httpFilters := []*hcm.HttpFilter{{
		Name:       wellknown.Router,
		ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
	}}

	httpRoutes := []*route.Route{
		{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: "upstream_cluster",
					},
				},
			},
		},
	}
	httpConnectionManager := &hcm.HttpConnectionManager{
		StatPrefix:               "ingress_http",
		CodecType:                hcm.HttpConnectionManager_AUTO,
		ForwardClientCertDetails: hcm.HttpConnectionManager_FORWARD_ONLY,
		HttpProtocolOptions:      &core.Http1ProtocolOptions{},
		Http2ProtocolOptions: &core.Http2ProtocolOptions{
			MaxConcurrentStreams:        &wrappers.UInt32Value{Value: 100},
			InitialStreamWindowSize:     &wrappers.UInt32Value{Value: 65536},   //64k
			InitialConnectionWindowSize: &wrappers.UInt32Value{Value: 1048576}, //1mb
		},
		HttpFilters: httpFilters,
		Tracing: &hcm.HttpConnectionManager_Tracing{
			RandomSampling: &envoytypev3.Percent{Value: 0.0},
		},
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &route.RouteConfiguration{
				VirtualHosts: []*route.VirtualHost{
					{
						Name:    "virtual_hosts",
						Domains: []string{"*"},
						Routes:  httpRoutes,
					},
				},
			},
		},
		NormalizePath:                &wrappers.BoolValue{Value: true},
		MergeSlashes:                 true,
		PathWithEscapedSlashesAction: hcm.HttpConnectionManager_UNESCAPE_AND_REDIRECT,
	}

	pbst, httpConnectionManagerErr := anypb.New(httpConnectionManager)
	if httpConnectionManagerErr != nil {
		panic(fmt.Errorf("anypb.New(httpConnectionManager, %v)", httpConnectionManagerErr))
	}

	tlsCertificatesSdsSecretConfigs := []*envoyauth.SdsSecretConfig{
		{
			Name:      "listener_certificate",
			SdsConfig: secretsConfig,
		},
	}
	tlsContext := &envoyauth.DownstreamTlsContext{
		CommonTlsContext: &envoyauth.CommonTlsContext{
			TlsParams: &envoyauth.TlsParameters{
				TlsMinimumProtocolVersion: envoyauth.TlsParameters_TLSv1_2,
			},
			AlpnProtocols:                  []string{"h2", "http/1.1"},
			TlsCertificateSdsSecretConfigs: tlsCertificatesSdsSecretConfigs,
			ValidationContextType: &envoyauth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &envoyauth.SdsSecretConfig{
					Name:      "listener_validation_context",
					SdsConfig: secretsConfig,
				},
			},
		},
	}

	tlsContextTypedConfig, tlsContextErr := anypb.New(tlsContext)
	if tlsContextErr != nil {
		panic(fmt.Errorf("anypb.New(tlsContext, %v)", tlsContextErr))
	}

	transportSocket := &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tlsContextTypedConfig,
		},
	}

	return &listener.Listener{
		Name: "listener",
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 7443,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: pbst,
						},
					},
				},
				TransportSocket: transportSocket,
			},
		},
	}
}

func makeSecrets() []types.Resource {
	return []types.Resource{
		&envoyauth.Secret{
			Name: "listener_validation_context",
			Type: &envoyauth.Secret_ValidationContext{
				ValidationContext: &envoyauth.CertificateValidationContext{
					TrustChainVerification: envoyauth.CertificateValidationContext_ACCEPT_UNTRUSTED,
				},
			},
		},
		&envoyauth.Secret{
			Name: "cluster_validation_context",
			Type: &envoyauth.Secret_ValidationContext{
				ValidationContext: &envoyauth.CertificateValidationContext{
					TrustChainVerification: envoyauth.CertificateValidationContext_ACCEPT_UNTRUSTED,
				},
			},
		},
		&envoyauth.Secret{
			Name: "listener_certificate",
			Type: &envoyauth.Secret_TlsCertificate{
				TlsCertificate: &envoyauth.TlsCertificate{
					CertificateChain: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: selfSignedCertificate,
						},
					},
					PrivateKey: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: selfSignedKey,
						},
					},
				},
			},
		},
	}
}

func makeHTTPListenerWithOAuth2() *listener.Listener {

	runtimeKey := "csrf.oauth.upstream_cluster"
	csrfPolicyPerService := &envoyhttpcsrf.CsrfPolicy{
		FilterEnabled: &core.RuntimeFractionalPercent{
			DefaultValue: &envoytypev3.FractionalPercent{
				Numerator:   100,
				Denominator: envoytypev3.FractionalPercent_HUNDRED,
			},
			RuntimeKey: runtimeKey,
		},
	}
	cfg, csrfErr := anypb.New(csrfPolicyPerService)
	if csrfErr != nil {
		panic(fmt.Errorf("anypb.New(CsrfPolicy, %v)", csrfErr))
	}

	oauth2 := &envoyhttpoauth2.OAuth2{
		Config: &envoyhttpoauth2.OAuth2Config{
			TokenEndpoint: &core.HttpUri{
				Uri: "https://oauth2.googleapis.com/token",
				HttpUpstreamType: &core.HttpUri_Cluster{
					Cluster: "oauth2_cluster",
				},
				Timeout: durationpb.New(30 * time.Second),
			},
			AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			Credentials: &envoyhttpoauth2.OAuth2Credentials{
				ClientId: "client_id",
				TokenSecret: &envoyauth.SdsSecretConfig{
					Name:      "oauth2_token_secret",
					SdsConfig: secretsConfig,
				},
				TokenFormation: &envoyhttpoauth2.OAuth2Credentials_HmacSecret{
					HmacSecret: &envoyauth.SdsSecretConfig{
						Name:      "oauth2_hmac_secret",
						SdsConfig: secretsConfig,
					},
				},
				CookieNames: nil,
			},
			RedirectUri: "https://%REQ(:authority)%/callback",
			RedirectPathMatcher: &envoytypematcherv3.PathMatcher{
				Rule: &envoytypematcherv3.PathMatcher_Path{
					Path: &envoytypematcherv3.StringMatcher{
						MatchPattern: &envoytypematcherv3.StringMatcher_Exact{
							Exact: "/callback",
						},
						IgnoreCase: false,
					},
				},
			},
			SignoutPath: &envoytypematcherv3.PathMatcher{
				Rule: &envoytypematcherv3.PathMatcher_Path{
					Path: &envoytypematcherv3.StringMatcher{
						MatchPattern: &envoytypematcherv3.StringMatcher_Exact{
							Exact: "/signout",
						},
						IgnoreCase: false,
					},
				},
			},
			ForwardBearerToken: true, // forwarding the bearer token is turned on by default
			AuthScopes:         []string{"email", "openid"},
			Resources:          nil,
		},
	}

	o2f, oauth2Err := anypb.New(oauth2)
	if oauth2Err != nil {
		panic(fmt.Errorf("anypb.New(OAuth2, %v)", oauth2Err))
	}

	routerConfig, routerConfigErr := anypb.New(&router.Router{})
	if routerConfigErr != nil {
		panic(fmt.Errorf("anypb.New(router.Router, %v)", routerConfigErr))
	}

	httpFilters := []*hcm.HttpFilter{
		{
			Name: "envoy.filters.http.csrf",
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: cfg,
			},
		},
		{
			Name: "envoy.filters.http.oauth2",
			ConfigType: &hcm.HttpFilter_TypedConfig{
				TypedConfig: o2f,
			},
		},
		{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		},
	}

	httpRoutes := []*route.Route{
		{
			Match: &route.RouteMatch{
				PathSpecifier: &route.RouteMatch_Prefix{
					Prefix: "/",
				},
			},
			Action: &route.Route_Route{
				Route: &route.RouteAction{
					ClusterSpecifier: &route.RouteAction_Cluster{
						Cluster: "upstream_cluster",
					},
				},
			},
		},
	}
	httpConnectionManager := &hcm.HttpConnectionManager{
		StatPrefix:               "ingress_http",
		CodecType:                hcm.HttpConnectionManager_AUTO,
		ForwardClientCertDetails: hcm.HttpConnectionManager_FORWARD_ONLY,
		HttpFilters:              httpFilters,
		Tracing: &hcm.HttpConnectionManager_Tracing{
			RandomSampling: &envoytypev3.Percent{Value: 0.0},
		},
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &route.RouteConfiguration{
				VirtualHosts: []*route.VirtualHost{
					{
						Name:    "virtual_hosts",
						Domains: []string{"*"},
						Routes:  httpRoutes,
					},
				},
			},
		},
		NormalizePath:                &wrappers.BoolValue{Value: true},
		MergeSlashes:                 true,
		PathWithEscapedSlashesAction: hcm.HttpConnectionManager_UNESCAPE_AND_REDIRECT,
	}

	pbst, httpConnectionManagerErr := anypb.New(httpConnectionManager)
	if httpConnectionManagerErr != nil {
		panic(fmt.Errorf("anypb.New(httpConnectionManager, %v)", httpConnectionManagerErr))
	}

	tlsCertificatesSdsSecretConfigs := []*envoyauth.SdsSecretConfig{
		{
			Name:      "listener_certificate",
			SdsConfig: secretsConfig,
		},
	}
	tlsContext := &envoyauth.DownstreamTlsContext{
		CommonTlsContext: &envoyauth.CommonTlsContext{
			TlsParams: &envoyauth.TlsParameters{
				TlsMinimumProtocolVersion: envoyauth.TlsParameters_TLSv1_2,
			},
			AlpnProtocols:                  []string{"h2", "http/1.1"},
			TlsCertificateSdsSecretConfigs: tlsCertificatesSdsSecretConfigs,
			ValidationContextType: &envoyauth.CommonTlsContext_ValidationContextSdsSecretConfig{
				ValidationContextSdsSecretConfig: &envoyauth.SdsSecretConfig{
					Name:      "listener_validation_context",
					SdsConfig: secretsConfig,
				},
			},
		},
	}

	tlsContextTypedConfig, tlsContextErr := anypb.New(tlsContext)
	if tlsContextErr != nil {
		panic(fmt.Errorf("anypb.New(tlsContext, %v)", tlsContextErr))
	}

	transportSocket := &core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &core.TransportSocket_TypedConfig{
			TypedConfig: tlsContextTypedConfig,
		},
	}

	return &listener.Listener{
		Name: "listener",
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: 7443,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{
			{
				Filters: []*listener.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &listener.Filter_TypedConfig{
							TypedConfig: pbst,
						},
					},
				},
				TransportSocket: transportSocket,
			},
		},
	}
}

func makeOAuth2Secrets() []types.Resource {
	return []types.Resource{
		&envoyauth.Secret{
			Name: "oauth2_validation_context",
			Type: &envoyauth.Secret_ValidationContext{
				ValidationContext: &envoyauth.CertificateValidationContext{
					TrustChainVerification: envoyauth.CertificateValidationContext_ACCEPT_UNTRUSTED,
				},
			},
		},
		&envoyauth.Secret{
			Name: "oauth2_token_secret",
			Type: &envoyauth.Secret_GenericSecret{
				GenericSecret: &envoyauth.GenericSecret{
					Secret: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: "token_secret",
						},
					},
				},
			},
		},
		&envoyauth.Secret{
			Name: "oauth2_hmac_secret",
			Type: &envoyauth.Secret_GenericSecret{
				GenericSecret: &envoyauth.GenericSecret{
					Secret: &core.DataSource{
						Specifier: &core.DataSource_InlineString{
							InlineString: "d5a25207215ac442e3f82e804a647cf9",
						},
					},
				},
			},
		},
	}
}
