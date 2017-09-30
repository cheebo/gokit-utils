package session

import (
	"time"
)

type SessionVerification int

const (
	NoVerify  SessionVerification = iota
	WhiteList SessionVerification = iota
)

type State string

const (
	State_Active  State = "active"
	State_Closed  State = "closed"
	State_Locked  State = "locked"
	State_Blocked State = "blocked"
	State_Expired State = "expired"
	State_Error   State = "error"
)

const (
	NothingFound string = "Nothing found"
)

type Session interface {
	Get(jti string) (State, error)
	Save(jti string, state State, exp time.Duration) error
	Delete(jti string) error
	Verify(jti string, verify SessionVerification) (State, error)
}
