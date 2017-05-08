package middleware

import (
	"context"
	stdhttp "net/http"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/transport/http"
)

const (
	JwtCookieName = "jwt"
)

func JwtCookieToHTTPContext(cookieName string) http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return ctx
		}

		return context.WithValue(ctx, jwt.JWTTokenContextKey, cookie.Value)
	}
}