package middleware

import (
	"context"
	stdhttp "net/http"

	"github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/transport/http"
)

const (
	JwtUrlParam = "jwt"
)

func JwtUrlToHTTPContext(jwtUrlParam string) http.RequestFunc {
	return func(ctx context.Context, r *stdhttp.Request) context.Context {
		token := r.FormValue(JwtUrlParam)
		if len(token) == 0 {
			return ctx
		}

		return context.WithValue(ctx, jwt.JWTTokenContextKey, token)
	}
}