package claims

// Registered claims from RFC 7519 section 4.1.
const (
	// KeyExpiresAt is the "exp" registered claim key.
	KeyExpiresAt = "exp"
	// KeyIssuedAt is the "iat" registered claim key.
	KeyIssuedAt = "iat"
	// KeyNotBefore is the "nbf" registered claim key.
	KeyNotBefore = "nbf"
	// KeyID is the "jti" registered claim key.
	KeyID = "jti"
	// KeyIssuer is the "iss" registered claim key.
	KeyIssuer = "iss"
	// KeyAudience is the "aud" registered claim key.
	KeyAudience = "aud"
	// KeySubject is the "sub" registered claim key.
	KeySubject = "sub"
)

// Common non-registered claim keys used by jwtsmith helpers.
const (
	// KeyGroups is the "groups" claim key.
	KeyGroups = "groups"
	// KeyRoles is the "roles" claim key.
	KeyRoles = "roles"
	// KeyScope is the "scope" claim key (OAuth2 style).
	KeyScope = "scope"
	// KeyPermissions is the "permissions" claim key.
	KeyPermissions = "permissions"
	// KeyEntitlements is the "entitlements" claim key.
	KeyEntitlements = "entitlements"

	// KeyName is the "name" claim key.
	KeyName = "name"
	// KeyFirstName is the "first_name" claim key.
	KeyFirstName = "first_name"
	// KeyLastName is the "last_name" claim key.
	KeyLastName = "last_name"
	// KeyUsername is the "username" claim key.
	KeyUsername = "username"
	// KeyUserType is the "user_type" claim key.
	KeyUserType = "user_type"
	// KeyEmail is the "email" claim key.
	KeyEmail = "email"
	// KeyTelephoneNumber is the "telephone_number" claim key.
	KeyTelephoneNumber = "telephone_number"

	// KeyTokenType is the "token_type" claim key.
	KeyTokenType = "token_type"
	// KeyClientID is the "client_id" claim key.
	KeyClientID = "client_id"
	// KeySessionID is the "session_id" claim key.
	KeySessionID = "session_id"
	// KeyDeviceID is the "device_id" claim key.
	KeyDeviceID = "device_id"
	// KeyIPAddress is the "ip_address" claim key.
	KeyIPAddress = "ip_address"
	// KeyUserAgent is the "user_agent" claim key.
	KeyUserAgent = "user_agent"
	// KeyAuthMethod is the "auth_method" claim key.
	KeyAuthMethod = "auth_method"

	// KeyOrganizationID is the "organization_id" claim key.
	KeyOrganizationID = "organization_id"
	// KeyDomain is the "domain" claim key.
	KeyDomain = "domain"
	// KeyTimeZone is the "time_zone" claim key.
	KeyTimeZone = "time_zone"
	// KeyLocale is the "locale" claim key.
	KeyLocale = "locale"
	// KeyPreferredLanguage is the "preferred_language" claim key.
	KeyPreferredLanguage = "preferred_language"
	// KeyIsAdmin is the "is_admin" claim key.
	KeyIsAdmin = "is_admin"
)
