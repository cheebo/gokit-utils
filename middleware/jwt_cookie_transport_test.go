package middleware_test

import (
	"testing"
	"github.com/cheebo/gokit-utils/middleware"
	"github.com/go-kit/kit/auth/jwt"
	"net/http"
	"context"
)

var (
	jwTokenCookie = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ28ta2l0In0.14M2VmYyApdSlV_LZ88ajjwuaLeIFplB8JpyNy0A19E"
)

func TestJwtCookieToHTTPContext(t *testing.T) {
	reqFunc := middleware.JwtCookieToHTTPContext(middleware.JwtCookieName)

	// When the cookie doesn't exist
	ctx := reqFunc(context.Background(), &http.Request{})

	if ctx.Value(jwt.JWTTokenContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// When the cookie has the value
	cookie := http.Cookie{
		Name: middleware.JwtCookieName,
		Value: jwTokenCookie,
	}

	req := http.Request{
		Header: http.Header{},
	}
	req.AddCookie(&cookie)
	ctx = reqFunc(context.Background(), &req)

	token := ctx.Value(jwt.JWTTokenContextKey).(string)
	if token != jwTokenCookie {
		t.Errorf("Context doesn't contain the expected encoded token value; expected: %s, got: %s", jwTokenCookie, token)
	}

}