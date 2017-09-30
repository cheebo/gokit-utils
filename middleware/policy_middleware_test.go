package middleware_test

import (
	"context"
	"github.com/cheebo/gokit-utils/middleware"
	"github.com/ory/ladon"
	manager "github.com/ory/ladon/manager/memory"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	policyLogin = &ladon.DefaultPolicy{
		Subjects:  []string{"user"},
		Resources: []string{"auth:login"},
		Actions:   []string{"login"},
		Effect:    ladon.AllowAccess,
	}
	policyAuthWildcard = &ladon.DefaultPolicy{
		Subjects:  []string{"user"},
		Resources: []string{"service:<.*>"},
		Actions:   []string{"create"},
		Effect:    ladon.AllowAccess,
	}
)

func loginPolicyReq(user map[string]interface{}) *ladon.Request {
	return &ladon.Request{
		Subject:  "user",
		Resource: "auth:login",
		Action:   "login",
	}
}

func keysPolicyReq(user map[string]interface{}) *ladon.Request {
	return &ladon.Request{
		Subject:  "admin",
		Resource: "service:resource",
		Action:   "action",
	}
}

func TestCheckPolicy(t *testing.T) {
	a := assert.New(t)

	ctx := context.WithValue(context.Background(), middleware.JwtUserContextKey, map[string]interface{}{
		"id": 1, "name": "John", "email": "john@example.com",
	})
	e := func(ctx context.Context, i interface{}) (interface{}, error) { return ctx, nil }

	warden := &ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	warden.Manager.Create(policyLogin)

	mware := middleware.CheckPolicy(warden, loginPolicyReq)(e)
	_, err := mware(ctx, struct{}{})
	a.NoError(err)

}

func TestCheckPolicyWildcard(t *testing.T) {
	a := assert.New(t)

	ctx := context.WithValue(context.Background(), middleware.JwtUserContextKey, map[string]interface{}{
		"id": 1, "name": "John", "email": "john@example.com",
	})
	e := func(ctx context.Context, i interface{}) (interface{}, error) { return ctx, nil }

	warden := &ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	warden.Manager.Create(policyAuthWildcard)

	mware := middleware.CheckPolicy(warden, keysPolicyReq)(e)
	_, err := mware(ctx, struct{}{})
	a.Error(err)

}
