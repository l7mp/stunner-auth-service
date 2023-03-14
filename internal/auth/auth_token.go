package auth

// InternalAuthToken represents a TURN authentication token provided to clients.
type InternalAuthToken struct {
	Username string
	Password string
	Ttl      int64
	Uris     []string
}
