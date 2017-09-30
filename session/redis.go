package session

import (
	"github.com/go-redis/redis"
	"github.com/pkg/errors"
	"time"
)

type redisSession struct {
	client redis.UniversalClient
}

func NewRedisSession(client redis.UniversalClient) Session {
	return &redisSession{
		client: client,
	}
}

func (r redisSession) Get(jti string) (State, error) {
	state, err := r.client.Get(jti).Result()
	if err != nil {
		if err.Error() == "EOF" {
			err = errors.New(NothingFound)
		}
		return State_Error, err
	}
	return State(state), nil
}

func (r redisSession) Save(jti string, state State, exp time.Duration) error {
	return r.client.Set(jti, string(state), exp).Err()
}

func (r redisSession) Delete(jti string) error {
	return r.client.Del(jti).Err()
}

func (r redisSession) Verify(jti string, verify SessionVerification) (State, error) {
	switch verify {
	case WhiteList:
		state, err := r.client.Get(jti).Result()
		if err != nil {
			return State_Error, err
		}
		return State(state), nil
	default:
		return State_Active, nil
	}
}
