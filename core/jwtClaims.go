package core

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JwtClaims struct {
	Uid    int64  `json:"uid"`
	App_id int    `json:"app_id"`
	Exp    int64  `json:"exp"`
	Email  string `json:"email"`
}

func (c *JwtClaims) Valid() error {
	if time.Unix(c.Exp, 0).Before(time.Now()) {
		return fmt.Errorf("token has expired")
	}
	return nil
}

func VerifyRefreshToken(tokenString string, secret string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	_, ok = claims["app_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("invalid app id in token")
	}
	_, ok = claims["email"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid email in token")
	}
	_, ok = claims["uid"].(int64)
	if !ok {
		return nil, fmt.Errorf("invalid user id in token")
	}
	_, ok = claims["exp"].(int64)
	if !ok {
		return nil, fmt.Errorf("invalid exp in token")
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}
