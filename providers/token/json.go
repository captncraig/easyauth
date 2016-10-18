package token

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/captncraig/easyauth"
)

//json store is a simple token store that keeps tokens in-memory,
//backed up to a local json file.
//Not suitable for high volume or high reliability
type jsonStore struct {
	path   string
	tokens map[string]*Token
	sync.RWMutex
}

func NewJsonStore(fname string) (TokenDataAccess, error) {
	j := &jsonStore{
		path:   fname,
		tokens: map[string]*Token{},
	}
	if err := j.read(); err != nil {
		return nil, err
	}
	return j, nil
}

func (j *jsonStore) read() error {
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return j.write()
		}
		return err
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	return decoder.Decode(&j.tokens)
}

func (j *jsonStore) write() error {
	f, err := os.Create(j.path)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	return encoder.Encode(j.tokens)
}

func (j *jsonStore) LookupToken(hash string) (*easyauth.User, error) {
	j.RLock()
	tok, ok := j.tokens[hash]
	j.RUnlock()
	if !ok {
		return nil, nil
	}
	return &easyauth.User{
		Access:   tok.Role,
		Method:   "token",
		Username: tok.User,
	}, nil
}

func (j *jsonStore) StoreToken(t *Token) error {
	j.Lock()
	defer j.Unlock()
	j.tokens[t.Hash] = t
	return j.write()
}
func (j *jsonStore) RevokeToken(hash string) error {
	j.Lock()
	defer j.Unlock()
	delete(j.tokens, hash)
	return j.write()
}

func (j *jsonStore) ListTokens() ([]*Token, error) {
	j.RLock()
	toks := make([]*Token, 0, len(j.tokens))
	for _, t := range j.tokens {
		toks = append(toks, t)
	}
	j.RUnlock()
	return toks, nil
}
