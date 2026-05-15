package verification

// Middleware wraps a Verifier with additional behavior, returning a new Verifier.
//
// Compose middleware with Chain to apply ordered behavior (logging, metrics, audit, etc.)
// without modifying the inner Verifier.
type Middleware func(Verifier) Verifier

// Chain composes middleware in left-to-right order: Chain(a, b, c)(v) returns a(b(c(v))).
//
// A nil-or-empty middleware list returns the input Verifier unchanged.
func Chain(mws ...Middleware) Middleware {
	return func(v Verifier) Verifier {
		for i := len(mws) - 1; i >= 0; i-- {
			if mws[i] == nil {
				continue
			}
			v = mws[i](v)
		}
		return v
	}
}
