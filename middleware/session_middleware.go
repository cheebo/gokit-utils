package middleware

import (
	"context"

	session "github.com/cheebo/gokit-utils/session"
	rest "github.com/cheebo/gorest"
	jwt "github.com/dgrijalva/jwt-go"
	kitjwt "github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/endpoint"
)

const (
	JwtUserContextKey = "JwtUserKey"
	JwtClaimsUserKey  = "user"
)

func Session(sess session.Session, verify session.SessionVerification) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			claims, ok := ctx.Value(kitjwt.JWTClaimsContextKey).(jwt.MapClaims)
			if !ok {
				return nil, rest.ErrorInternal("Internal error")
			}

			jti, ok := claims["jti"]
			if !ok {
				return nil, rest.ErrorInternal("Internal error")
			}

			user, ok := claims[JwtClaimsUserKey]
			if !ok {
				return nil, rest.ErrorInternal("Internal error")
			}

			if verify != session.NoVerify {
				state, err := sess.Verify(jti.(string), verify)
				if err != nil {
					return nil, kitjwt.ErrTokenNotActive
				}

				switch state {
				case session.State_Locked:
					return "", rest.ErrorLocked("Locked")
				case session.State_Error:
					return "", rest.ErrorInternal("Internal error")
				case session.State_Blocked:
					return "", rest.AccessForbidden()
				case session.State_Expired:
					return "", rest.AccessForbidden()
				case session.State_Closed:
					return "", rest.AccessForbidden()
				}
			}

			ctx = context.WithValue(ctx, JwtUserContextKey, user)

			return next(ctx, request)
		}
	}
}
