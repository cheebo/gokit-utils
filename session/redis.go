package session

import (
	"github.com/go-redis/redis"
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

func (r redisSession) Save(jti string, state SessionState, exp time.Duration) error {
	return r.client.Set(jti, string(state), exp).Err()
}

func (r redisSession) Delete(jti string) error {
	return r.client.Del(jti).Err()
}

func (r redisSession) Verify(jti string, verify SessionVerification) (SessionState, error) {
	switch verify {
	case WhiteList:
		state, err := r.client.Get(jti).Result()
		if err != nil {
			return SessionState_Error, err
		}
		return SessionState(state), nil
	default:
		return SessionState_Active, nil
	}
}