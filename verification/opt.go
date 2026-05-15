package verification

// Opt configures a Verifier at construction.
type Opt func(*verifier)

// WithStaticChecks registers TokenCheckFunc that run on every Verify call,
// before any per-call extras passed to Verify.
func WithStaticChecks(checks ...TokenCheckFunc) Opt {
	return func(v *verifier) { v.staticCheck = append(v.staticCheck, checks...) }
}
