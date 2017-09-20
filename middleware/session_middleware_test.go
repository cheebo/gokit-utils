package middleware

import (
	"context"
	"testing"
	"time"

	kitjwt "github.com/go-kit/kit/auth/jwt"
	jwt "github.com/dgrijalva/jwt-go"

	"github.com/cheebo/gokit-utils/session"
	"github.com/cheebo/gokit-utils/middleware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/cheebo/gorest"
)

type JwtUser struct {
	Id            string
	Name          string
	Email         string
}

var (
	jwtUser = JwtUser{
		Id: "100",
		Name: "John Doe",
		Email: "jhondoe@example.com",
	}
)

type sessionMock struct {
	mock.Mock
}
func (s sessionMock) Save(jti string, state session.SessionState, exp time.Duration) error {
	return nil
}
func (s sessionMock) Delete(jti string) error {
	return nil
}
func (s sessionMock) Verify(jti string, verify session.SessionVerification) (session.SessionState, error) {
	return session.SessionState(jti), nil
}

func TestSession(t *testing.T) {
	assert := assert.New(t)

	e := func(ctx context.Context, i interface{}) (interface{}, error) { return ctx, nil }

	mockedSession := sessionMock{}

	// WhiteListing
	// No Claims is passed into the session
	mware := middleware.Session(mockedSession, session.WhiteList)(e)
	_, err := mware(context.Background(), struct{}{})

	assert.Error(err, "Session should return an error")
	assert.EqualError(err, rest.ErrorInternal("Internal error").Error())



	// Bad claims passed
	badClaims := jwt.MapClaims{}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx := context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, badClaims)
	_, err = mware(ctx, struct{}{})

	assert.Error(err, "Session should return an error")
	assert.EqualError(err, rest.ErrorInternal("Internal error").Error())



	// Bad claims without jti claims passed
	badClaims = jwt.MapClaims{
		middleware.JwtClaimsUserKey: jwtUser,
	}

	mware = middleware.Session(mockedSession, session.WhiteList)(e)

	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, badClaims)
	_, err = mware(ctx, struct{}{})

	assert.Error(err, "Session should return an error")
	assert.EqualError(err, rest.ErrorInternal("Internal error").Error())



	// Bad claims without user, but with jti claims passed
	badClaims = jwt.MapClaims{
		"jti": string(session.SessionState_Active),
	}

	mware = middleware.Session(mockedSession, session.WhiteList)(e)

	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, badClaims)
	_, err = mware(ctx, struct{}{})

	assert.Error(err, "Session should return an error")
	assert.EqualError(err, rest.ErrorInternal("Internal error").Error())



	// Good claims, session active
	claims := jwt.MapClaims{
		"jti": string(session.SessionState_Active),
		middleware.JwtClaimsUserKey: jwtUser,
	}

	mware = middleware.Session(mockedSession, session.WhiteList)(e)

	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	ctx1, err := mware(ctx, struct{}{})
	ctxUser, ok := ctx1.(context.Context).Value(middleware.JwtUserContextKey).(JwtUser)
	if !ok {
		t.Fatal("Claims were not passed into context correctly")
	}

	assert.Equal(jwtUser, ctxUser)



	// LOCKED
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Locked),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.EqualError(err, rest.ErrorLocked().Error())

	// Blocked
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Blocked),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.EqualError(err, rest.AccessForbidden().Error())

	// Blocked
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Expired),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.EqualError(err, rest.AccessForbidden().Error())

	// Closed
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Closed),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.EqualError(err, rest.AccessForbidden().Error())

	// Error
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Error),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(mockedSession, session.WhiteList)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.EqualError(err, rest.ErrorInternal("Internal error").Error())


	// NoVerify
	claims = jwt.MapClaims{
		"jti": string(session.SessionState_Error),
		middleware.JwtClaimsUserKey: jwtUser,
	}
	mware = middleware.Session(nil, session.NoVerify)(e)
	ctx = context.WithValue(context.Background(), kitjwt.JWTClaimsContextKey, claims)
	_, err = mware(ctx, struct{}{})
	assert.NoError(err)
}