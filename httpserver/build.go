package httpserver

import (
	"fmt"

	"github.com/dcadolph/jwtsmith/jwks"
	"github.com/dcadolph/jwtsmith/pkgerr"
	"github.com/dcadolph/jwtsmith/verification"
)

// buildVerifier returns a single-key verifier when no AdditionalKeys are configured,
// otherwise a multi-key verifier covering the primary plus all AdditionalKeys. When
// cfg.Revoker is set it is registered as a verifier-wide check.
func buildVerifier(cfg Config) (verification.Verifier, error) {

	var opts []verification.Opt
	if cfg.Revoker != nil {
		opts = append(opts, verification.WithRevoker(cfg.Revoker))
	}

	if len(cfg.AdditionalKeys) == 0 {
		return verification.NewVerifier(cfg.Method, cfg.PublicKey, opts...)
	}

	if cfg.Kid == "" {
		return nil, fmt.Errorf(
			"%w: Kid required on the primary key when AdditionalKeys is set (multi-key dispatches by kid)",
			pkgerr.ErrInvalidValue,
		)
	}

	entries := make([]verification.KeyEntry, 0, 1+len(cfg.AdditionalKeys))
	entries = append(entries, verification.KeyEntry{
		Kid:       cfg.Kid,
		Method:    cfg.Method,
		PublicKey: cfg.PublicKey,
	})
	entries = append(entries, cfg.AdditionalKeys...)
	return verification.NewMultiKeyVerifier(entries, opts...)
}

// buildJWKS produces the JWKS payload published at /.well-known/jwks.json. Includes the
// primary key plus every AdditionalKey, each tagged with its alg.
func buildJWKS(cfg Config) (jwks.JWKS, error) {

	out := jwks.JWKS{Keys: make([]jwks.JWK, 0, 1+len(cfg.AdditionalKeys))}

	primary, err := jwks.JWKFromPublicKey(cfg.PublicKey, cfg.Kid)
	if err != nil {
		return jwks.JWKS{}, err
	}
	primary.Alg = cfg.Method.Alg()
	out.Keys = append(out.Keys, primary)

	for i, e := range cfg.AdditionalKeys {
		j, err := jwks.JWKFromPublicKey(e.PublicKey, e.Kid)
		if err != nil {
			return jwks.JWKS{}, fmt.Errorf("AdditionalKeys[%d] (%s): %w", i, e.Kid, err)
		}
		j.Alg = e.Method.Alg()
		out.Keys = append(out.Keys, j)
	}
	return out, nil
}
