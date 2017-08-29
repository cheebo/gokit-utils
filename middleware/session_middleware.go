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
	JwtUserKey = "JwtUserKey"
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

			user, ok := claims["user"]
			if !ok {
				return nil, rest.ErrorInternal("Internal error")
			}

			if verify != session.NoVerify {
				state, err := sess.Verify(jti.(string), verify)
				if err != nil {
					return nil, kitjwt.ErrTokenNotActive
				}

				switch state {
				case session.SessionState_Locked:
					return "", rest.ErrorLocked()
				case session.SessionState_Error:
					return "", rest.ErrorInternal("Internal error")
				case session.SessionState_Blocked:
					return "", rest.AccessForbidden()
				case session.SessionState_Expired:
					return "", rest.AccessForbidden()
				case session.SessionState_Closed:
					return "", rest.AccessForbidden()
				}
			}

			ctx = context.WithValue(ctx, JwtUserKey, user)

			return next(ctx, request)
		}
	}
}
