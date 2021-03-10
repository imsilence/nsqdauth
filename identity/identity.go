package identity

import (
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/imsilence/nsqdauth/utils"
)

// Authorization 权限
type Authorization struct {
	Topic       string   `json:"topic"`
	Channels    []string `json:"channels"`
	Permissions []string `json:"permissions"`
}

// Identity 身份
type Identity struct {
	Username       string
	Password       string
	Authorizations []Authorization
}

// Valid 验证密码
func (i *Identity) Valid(password string) bool {
	return utils.Md5(password) == i.Password
}

// Identities 身份信息
type Identities map[string]*Identity

// ParseIdentity 解析身份信息
func ParseIdentity(db string) (Identities, error) {
	identities := make(Identities)

	fhandler, err := os.Open(db)
	if err != nil {
		return identities, err
	}

	defer fhandler.Close()

	reader := csv.NewReader(fhandler)
	for {
		line, err := reader.Read()
		if err != nil {
			if err != io.EOF {
				log.Println("error read identity csv:", err)
			}
			break
		}
		if len(line) < 5 {
			log.Println("error parse indentity:", line)
			continue
		}

		if strings.HasPrefix(line[0], "#") {
			continue
		}

		username := line[0]
		password := line[1]

		authorization := Authorization{
			Topic:       line[2],
			Channels:    strings.Split(line[3], ";"),
			Permissions: strings.Split(line[4], ";"),
		}

		if _, ok := identities[username]; ok {
			identities[username].Authorizations = append(identities[username].Authorizations, authorization)
		} else {
			identities[username] = &Identity{
				Username:       username,
				Password:       password,
				Authorizations: []Authorization{authorization},
			}
		}
	}

	return identities, nil
}

// Valid 验证身份
func (i Identities) Valid(username, password string) (error, *Identity) {
	if identity, ok := i[username]; ok && identity.Valid(password) {
		return nil, identity
	}

	return fmt.Errorf("username or password is invalid"), nil
}
