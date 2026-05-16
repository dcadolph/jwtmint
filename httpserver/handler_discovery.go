package httpserver

import (
	"net/http"
	"strings"

	"github.com/dcadolph/jwtmint/internal/jsonutil"
)

// discoveryDoc is the subset of OIDC discovery fields jwtmintd publishes.
//
// jwtmintd is not a full OIDC provider; this document exists so OIDC libraries that
// expect /.well-known/openid-configuration can auto-discover the JWKS URI and signing
// algorithms. Token endpoint, userinfo endpoint, and other OIDC features are not provided.
type discoveryDoc struct {
	Issuer                           string   `json:"issuer"`
	JWKSURI                          string   `json:"jwks_uri"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
}

// handleOIDCDiscovery returns a handler that publishes the OIDC discovery document.
//
// issuer must match what tokens carry as the "iss" claim — typically the publicly-reachable
// scheme://host[:port] of jwtmintd. algs lists every signing alg the JWKS includes.
func handleOIDCDiscovery(issuer string, algs []string) http.HandlerFunc {

	doc := discoveryDoc{
		Issuer:                           strings.TrimRight(issuer, "/"),
		JWKSURI:                          strings.TrimRight(issuer, "/") + "/.well-known/jwks.json",
		IDTokenSigningAlgValuesSupported: algs,
		ResponseTypesSupported:           []string{"id_token"},
		SubjectTypesSupported:            []string{"public"},
	}
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = jsonutil.Write(w, http.StatusOK, doc)
	}
}
