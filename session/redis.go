package session

import (
	"github.com/go-redis/redis"
	"fmt"
	"time"
)

type redisSession struct {
	client *redis.Client
}

func NewRedisSession(client *redis.Client) Session {
	return &redisSession{
		client: client,
	}
}

func (r redisSession) Save(userId string, jti string, state SessionState, exp time.Duration) error {
	return r.client.Set(sessionId(userId, jti), state, exp).Err()
}

func (r redisSession) Delete(userId string, jti string) error {
	return r.client.Del(sessionId(userId, jti)).Err()
}

func (r redisSession) Verify(userId string, jti string, verify SessionVerification) (SessionState, error) {
	switch verify {
	case WhiteList:
		state, err := r.client.Get(sessionId(userId, jti)).Result()
		if err != nil {
			return SessionState_Error, err
		}
		return SessionState(state), nil
	default:
		return SessionState_Active, nil
	}
}

func sessionId(userId string, jti string) string {
	return fmt.Sprintf("%s-%s", userId, jti)
}