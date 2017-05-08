package middleware_test

import (
	"testing"
	"github.com/cheebo/gokit-utils/middleware"
	"github.com/go-kit/kit/auth/jwt"
	"net/url"
	"net/http"
	"context"
)

var (
	jwToken = "eyJhbGciOiJIUzI1NiIsImtpZCI6ImtpZCIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ28ta2l0In0.14M2VmYyApdSlV_LZ88ajjwuaLeIFplB8JpyNy0A19E"
)

func TestJwtUrlToHTTPContext(t *testing.T) {
	reqFunc := middleware.JwtUrlToHTTPContext(middleware.JwtUrlParam)

	// When the url param doesn't exist
	ctx := reqFunc(context.Background(), &http.Request{})

	if ctx.Value(jwt.JWTTokenContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// URL value has invalid format
	u, _ := url.Parse("http://exmaple.com/?"+middleware.JwtUrlParam+"=")
	ctx = reqFunc(context.Background(), &http.Request{URL: u})

	if ctx.Value(jwt.JWTTokenContextKey) != nil {
		t.Error("Context shouldn't contain the encoded JWT")
	}

	// URL value is correct
	u, _ = url.Parse("http://exmaple.com/?"+middleware.JwtUrlParam+"="+jwToken)
	ctx = reqFunc(context.Background(), &http.Request{URL: u})

	token := ctx.Value(jwt.JWTTokenContextKey).(string)
	if token != jwToken {
		t.Errorf("Context doesn't contain the expected encoded token value; expected: %s, got: %s", jwToken, token)
	}
}
