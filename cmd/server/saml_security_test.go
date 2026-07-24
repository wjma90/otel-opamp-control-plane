package main

import (
	"testing"

	"github.com/crewjam/saml"
)

func TestSAMLSSOEndpointsRequireConfidentialTransport(t *testing.T) {
	for _, test := range []struct {
		name     string
		endpoint saml.Endpoint
	}{
		{
			name: "redirect location",
			endpoint: saml.Endpoint{
				Binding:  saml.HTTPRedirectBinding,
				Location: "http://identity.example.test/sso",
			},
		},
		{
			name: "post location",
			endpoint: saml.Endpoint{
				Binding:  saml.HTTPPostBinding,
				Location: "http://identity.example.test/sso",
			},
		},
		{
			name: "response location",
			endpoint: saml.Endpoint{
				Binding:          saml.HTTPRedirectBinding,
				Location:         "https://identity.example.test/sso",
				ResponseLocation: "http://identity.example.test/response",
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := &saml.EntityDescriptor{IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SingleSignOnServices: []saml.Endpoint{test.endpoint},
			}}}
			if err := validateSAMLSSOEndpoints(metadata); err == nil {
				t.Fatal("unsafe SAML SSO endpoint was accepted")
			}
		})
	}
}

func TestSAMLSSOEndpointsAllowHTTPSAndLoopbackMocks(t *testing.T) {
	metadata := &saml.EntityDescriptor{IDPSSODescriptors: []saml.IDPSSODescriptor{{
		SingleSignOnServices: []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: "https://identity.example.test/sso"},
			{Binding: saml.HTTPPostBinding, Location: "http://127.0.0.1:8081/sso"},
		},
	}}}
	if err := validateSAMLSSOEndpoints(metadata); err != nil {
		t.Fatalf("valid SAML SSO endpoints were rejected: %v", err)
	}
}

func TestSAMLMetadataRequiresSupportedSSOBinding(t *testing.T) {
	metadata := &saml.EntityDescriptor{IDPSSODescriptors: []saml.IDPSSODescriptor{{
		SingleSignOnServices: []saml.Endpoint{{
			Binding:  saml.HTTPArtifactBinding,
			Location: "https://identity.example.test/artifact",
		}},
	}}}
	if err := validateSAMLSSOEndpoints(metadata); err == nil {
		t.Fatal("metadata without Redirect or POST SSO endpoint was accepted")
	}
}
