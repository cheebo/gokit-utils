package session

import (
	"time"
)

type dumbSession struct {
	// empty
}

func NewDumbSession() Session {
	return &redisSession{}
}

func (r dumbSession) Get(jti string) (SessionState, error) {
	return SessionState_Active, nil
}

func (r dumbSession) Save(jti string, state SessionState, exp time.Duration) error {
	return nil
}

func (r dumbSession) Delete(jti string) error {
	return nil
}

func (r dumbSession) Verify(jti string, verify SessionVerification) (SessionState, error) {
	return SessionState_Active, nil
}
