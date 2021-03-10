package session

import (
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/imsilence/nsqdauth/identity"
)

// Session 会话信息
type Session struct {
	mux     *sync.RWMutex
	secrets map[string]*identity.Identity
}

// NewSession 创建会话
func NewSession() *Session {
	return &Session{
		mux:     &sync.RWMutex{},
		secrets: make(map[string]*identity.Identity),
	}
}

// Get 获取会话
func (s *Session) Get(secret string) (*identity.Identity, error) {
	s.mux.RLock()
	identity, ok := s.secrets[secret]
	s.mux.RUnlock()

	if ok {
		return identity, nil
	} else {
		return nil, fmt.Errorf("not found")
	}
}

// Set 存储会话
func (s *Session) Set(identity *identity.Identity) string {
	secret := uuid.New().String()
	s.mux.Lock()
	s.secrets[secret] = identity
	s.mux.Unlock()
	return secret
}
