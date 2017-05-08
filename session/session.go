package session

import (
	"time"
)

type SessionVerification int
const (
	NoVerify  SessionVerification = iota
	WhiteList SessionVerification = iota
)

type SessionState string
const (
	SessionState_Active  SessionState = "active"
	SessionState_Closed  SessionState = "closed"
	SessionState_Locked  SessionState = "locked"
	SessionState_Blocked SessionState = "blocked"
	SessionState_Expired SessionState = "expired"
	SessionState_Error   SessionState = "error"
)


type Session interface {
	Save(userId string, jti string, state SessionState, exp time.Duration) error
	Delete(userId string, jti string) error
	Verify(userId string, jti string, verify SessionVerification) (SessionState, error)
}