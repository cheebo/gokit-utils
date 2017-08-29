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

func (r dumbSession) Save(userId string, jti string, state SessionState, exp time.Duration) error {
	return nil
}

func (r dumbSession) Delete(userId string, jti string) error {
	return nil
}

func (r dumbSession) Verify(userId string, jti string, verify SessionVerification) (SessionState, error) {
	return SessionState_Active, nil
}
