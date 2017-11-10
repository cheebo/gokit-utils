# gokit-utils
Transport and middleware for go-kit framework

# Session
`session/session.go` contains session interface (CRUD + Verify)

```go
type Session interface {
	Get(jti string) (State, error)
	Save(jti string, state State, exp time.Duration) error
	Delete(jti string) error
	Verify(jti string, verify SessionVerification) (State, error)
}
```


`session/redis.go` contains Session implementation for Redis

# Middleware
- JwtCookieToHTTPContext - takes JWT from cookie and passes to context
- JwtUrlToHTTPContext - takes JWT from URL and passes to context
- Session - verifys session. 

Session can be in one of the possible states: {active, locked, blocked, closed, expired and error}.
Valid session is in active state, otherwise session is invalid and middleware returns error.
