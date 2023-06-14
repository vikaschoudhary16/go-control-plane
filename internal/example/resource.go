// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

package example

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoyhttpoauth2 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoyauth "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstreams_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	envoytypematcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	"github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/golang/protobuf/ptypes/wrappers"
)

const (
	ClusterName  = "example_proxy_cluster"
	RouteName    = "local_route"
	ListenerName = "listener_0"
	//ListenerPort = 10000
	ListenerPort = 8000
	//UpstreamHost = "www.envoyproxy.io"
	UpstreamHost          = "127.0.0.1"
	UpstreamPort          = 8085
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
)

var (
	adsConfig = &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_Ads{
			Ads: &core.AggregatedConfigSource{},
		},
	}

	secretsConfig = adsConfig
)

func makeCluster(clusterName string) *cluster.Cluster {
	return &cluster.Cluster{
		Name:                 clusterName,
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_EDS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		//LoadAssignment:       makeEndpoint(clusterName),
		EdsClusterConfig: &cluster.Cluster_EdsClusterConfig{
			EdsConfig: &core.ConfigSource{
				ConfigSourceSpecifier: &core.ConfigSource_Ads{},
			},
			ServiceName: clusterName,
		},
		DnsLookupFamily: cluster.Cluster_V4_ONLY,
	}
}

func makeOktaCluster() *cluster.Cluster {
	tlsContext := &envoyauth.UpstreamTlsContext{
		CommonTlsContext: &envoyauth.CommonTlsContext{
			TlsParams: &envoyauth.TlsParameters{
				TlsMinimumProtocolVersion: envoyauth.TlsParameters_TLSv1_2,
			},
		},
		Sni: "dev-96701052-admin.okta.com",
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
	return &cluster.Cluster{
		Name:                 "okta.ad",
		ConnectTimeout:       durationpb.New(5 * time.Second),
		ClusterDiscoveryType: &cluster.Cluster_Type{Type: cluster.Cluster_LOGICAL_DNS},
		LbPolicy:             cluster.Cluster_ROUND_ROBIN,
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "okta.ad",
			Endpoints: []*endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*endpoint.LbEndpoint{{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_SocketAddress{
									SocketAddress: &core.SocketAddress{
										//Protocol: core.SocketAddress_TCP,
										Address: "dev-96701052.okta.com",
										PortSpecifier: &core.SocketAddress_PortValue{
											PortValue: 443,
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
		DnsLookupFamily: cluster.Cluster_V4_ONLY,
		TransportSocket: transportSocket,
	}
}

func makeEndpoint(clusterName string) *endpoint.ClusterLoadAssignment {
	return &endpoint.ClusterLoadAssignment{
		ClusterName: clusterName,
		Endpoints: []*endpoint.LocalityLbEndpoints{{
			LbEndpoints: []*endpoint.LbEndpoint{{
				HostIdentifier: &endpoint.LbEndpoint_Endpoint{
					Endpoint: &endpoint.Endpoint{
						Address: &core.Address{
							Address: &core.Address_SocketAddress{
								SocketAddress: &core.SocketAddress{
									Protocol: core.SocketAddress_TCP,
									Address:  UpstreamHost,
									PortSpecifier: &core.SocketAddress_PortValue{
										PortValue: UpstreamPort,
									},
								},
							},
						},
					},
				},
			}},
		}},
	}
}

func makeRoute(routeName string, clusterName string) *route.RouteConfiguration {
	return &route.RouteConfiguration{
		Name: routeName,
		VirtualHosts: []*route.VirtualHost{{
			Name:    "local_service",
			Domains: []string{"*"},
			Routes: []*route.Route{{
				Match: &route.RouteMatch{
					PathSpecifier: &route.RouteMatch_Prefix{
						Prefix: "/",
					},
				},
				Action: &route.Route_Route{
					Route: &route.RouteAction{
						ClusterSpecifier: &route.RouteAction_Cluster{
							Cluster: clusterName,
						},
						// HostRewriteSpecifier: &route.RouteAction_HostRewriteLiteral{
						// 	HostRewriteLiteral: UpstreamHost,
						// },
					},
				},
			}},
		}},
	}
}

func makeHTTPListener(listenerName string, route string) *listener.Listener {
	routerConfig, _ := anypb.New(&router.Router{})
	// HTTP filter configuration
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "http",
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: route,
			},
		},
		HttpFilters: []*hcm.HttpFilter{{
			Name:       wellknown.Router,
			ConfigType: &hcm.HttpFilter_TypedConfig{TypedConfig: routerConfig},
		}},
	}
	pbst, err := anypb.New(manager)
	if err != nil {
		panic(err)
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
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: ListenerPort,
					},
				},
			},
		},
		FilterChains: []*listener.FilterChain{{
			Filters: []*listener.Filter{{
				Name: wellknown.HTTPConnectionManager,
				ConfigType: &listener.Filter_TypedConfig{
					TypedConfig: pbst,
				},
			}},
			TransportSocket: transportSocket,
		}},
	}
}

func makeConfigSource() *core.ConfigSource {
	source := &core.ConfigSource{}
	source.ResourceApiVersion = resource.DefaultAPIVersion
	source.ConfigSourceSpecifier = &core.ConfigSource_ApiConfigSource{
		ApiConfigSource: &core.ApiConfigSource{
			TransportApiVersion:       resource.DefaultAPIVersion,
			ApiType:                   core.ApiConfigSource_GRPC,
			SetNodeOnFirstMessageOnly: true,
			GrpcServices: []*core.GrpcService{{
				TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &core.GrpcService_EnvoyGrpc{ClusterName: "xds_cluster"},
				},
			}},
		},
	}
	return source
}

func makeTlsCluster(clusterName string) *cluster.Cluster {

	tlsContext := &envoyauth.UpstreamTlsContext{
		CommonTlsContext: &envoyauth.CommonTlsContext{
			TlsParams: &envoyauth.TlsParameters{
				TlsMinimumProtocolVersion: envoyauth.TlsParameters_TLSv1_2,
			},
			AlpnProtocols: []string{"h2", "http/1.1"},
			// ValidationContextType: &envoyauth.CommonTlsContext_ValidationContextSdsSecretConfig{
			// 	ValidationContextSdsSecretConfig: &envoyauth.SdsSecretConfig{
			// 		Name:      "cluster_validation_context",
			// 		SdsConfig: secretsConfig,
			// 	},
			// },
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

func makeHTTPListenerWithOAuth2(listenerName string, routename string) *listener.Listener {
	// runtimeKey := "csrf.oauth.upstream_cluster"
	// csrfPolicyPerService := &envoyhttpcsrf.CsrfPolicy{
	// 	FilterEnabled: &core.RuntimeFractionalPercent{
	// 		DefaultValue: &envoytypev3.FractionalPercent{
	// 			Numerator:   100,
	// 			Denominator: envoytypev3.FractionalPercent_HUNDRED,
	// 		},
	// 		RuntimeKey: runtimeKey,
	// 	},
	// }
	// cfg, csrfErr := anypb.New(csrfPolicyPerService)
	// if csrfErr != nil {
	// 	panic(fmt.Errorf("anypb.New(CsrfPolicy, %v)", csrfErr))
	// }

	oauth2 := &envoyhttpoauth2.OAuth2{
		Config: &envoyhttpoauth2.OAuth2Config{
			TokenEndpoint: &core.HttpUri{
				Uri: "https://dev-96701052.okta.com/oauth2/default/v1/token",
				HttpUpstreamType: &core.HttpUri_Cluster{
					Cluster: "okta.ad",
				},
				Timeout: durationpb.New(30 * time.Second),
			},
			AuthorizationEndpoint: "https://dev-96701052.okta.com/oauth2/default/v1/authorize",
			Credentials: &envoyhttpoauth2.OAuth2Credentials{
				ClientId: "0oa9k6rotqgMMNsPA5d7",
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
			//RedirectUri: "http://%REQ(:authority)%/bearer",
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
			PassThroughMatcher: []*route.HeaderMatcher{&route.HeaderMatcher{
				Name: "authorization",
				HeaderMatchSpecifier: &route.HeaderMatcher_PrefixMatch{
					PrefixMatch: "Bearer",
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
			//AuthScopes:         []string{"email", "openid", "offline_access"},
			Resources: nil,
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
		// {
		// 	Name: "envoy.filters.http.csrf",
		// 	ConfigType: &hcm.HttpFilter_TypedConfig{
		// 		TypedConfig: cfg,
		// 	},
		// },
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

	// httpRoutes := []*route.Route{
	// 	{
	// 		Match: &route.RouteMatch{
	// 			PathSpecifier: &route.RouteMatch_Prefix{
	// 				Prefix: "/",
	// 			},
	// 		},
	// 		Action: &route.Route_Route{
	// 			Route: &route.RouteAction{
	// 				ClusterSpecifier: &route.RouteAction_Cluster{
	// 					Cluster: "upstream_cluster",
	// 				},
	// 			},
	// 		},
	// 	},
	// }
	httpConnectionManager := &hcm.HttpConnectionManager{
		StatPrefix: "ingress_http",
		CodecType:  hcm.HttpConnectionManager_AUTO,
		//ForwardClientCertDetails: hcm.HttpConnectionManager_FORWARD_ONLY,
		HttpFilters: httpFilters,
		// Tracing: &hcm.HttpConnectionManager_Tracing{
		// 	RandomSampling: &envoytypev3.Percent{Value: 0.0},
		// },
		RouteSpecifier: &hcm.HttpConnectionManager_Rds{
			Rds: &hcm.Rds{
				ConfigSource:    makeConfigSource(),
				RouteConfigName: routename,
			},
		},
		// NormalizePath:                &wrappers.BoolValue{Value: true},
		// MergeSlashes:                 true,
		// PathWithEscapedSlashesAction: hcm.HttpConnectionManager_UNESCAPE_AND_REDIRECT,
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
		Name: listenerName,
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Protocol: core.SocketAddress_TCP,
					Address:  "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: ListenerPort,
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

func makeOAuth2Secrets() []types.Resource {
	return []types.Resource{
		// &envoyauth.Secret{
		// 	Name: "oauth2_validation_context",
		// 	Type: &envoyauth.Secret_ValidationContext{
		// 		ValidationContext: &envoyauth.CertificateValidationContext{
		// 			TrustChainVerification: envoyauth.CertificateValidationContext_ACCEPT_UNTRUSTED,
		// 		},
		// 	},
		// },
		&envoyauth.Secret{
			Name: "oauth2_token_secret",
			Type: &envoyauth.Secret_GenericSecret{
				GenericSecret: &envoyauth.GenericSecret{
					Secret: &core.DataSource{
						Specifier: &core.DataSource_InlineBytes{
							InlineBytes: []byte("5VFEeLfEK_MWzypJu0pFStVjJeCUMBlvUkpAyYkr"),
						},
					},
				},
			},
		},
		// &envoyauth.Secret{
		// 	Name: "oauth2_hmac_secret",
		// 	Type: &envoyauth.Secret_GenericSecret{
		// 		GenericSecret: &envoyauth.GenericSecret{
		// 			Secret: &core.DataSource{
		// 				Specifier: &core.DataSource_InlineBytes{
		// 					//InlineBytes: []byte("cmFRaXd6TEpNSlpmVysvWWM4NmQvQmkwOXF1dU1VWWNXYW9tdWQvbjVlRT0K"),
		// 					InlineBytes: []byte("RaXd6TEpNSlpmVysvWWM4NmQvQmkwOXF1dU1VWWNXYW9tdWQvbjVlRT0K"),
		// 				},
		// 			},
		// 		},
		// 	},
		// },
	}
}

func GenerateSnapshot(version string) *cache.Snapshot {
	cluster := ClusterName + "-" + version
	snap, _ := cache.NewSnapshot(version,
		map[resource.Type][]types.Resource{
			resource.ClusterType: {makeTlsCluster(cluster), makeOktaCluster()},
			resource.RouteType:   {makeRoute(RouteName, cluster)},
			//resource.ListenerType: {makeHTTPListener(ListenerName, RouteName)},
			resource.ListenerType: {makeHTTPListenerWithOAuth2(ListenerName, RouteName)},
			resource.SecretType:   append(makeSecrets(), makeOAuth2Secrets()...),
		},
	)
	return snap
}
