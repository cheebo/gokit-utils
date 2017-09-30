package middleware

import (
	"context"

	rest "github.com/cheebo/gorest"
	"github.com/go-kit/kit/endpoint"
	"github.com/ory/ladon"
)

type PolicyRequest func(map[string]interface{}) *ladon.Request

func CheckPolicy(warden *ladon.Ladon, policy PolicyRequest) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			user, ok := ctx.Value(JwtUserContextKey).(map[string]interface{})
			if !ok {
				return nil, rest.AccessForbidden()
			}

			err = warden.IsAllowed(policy(user))
			if err != nil {
				return nil, rest.AccessForbidden()
			}

			return next(ctx, request)
		}
	}
}
