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

func VerifyRefreshToken(tokenString string, secret string) (JwtClaims, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return JwtClaims{}, err
	}
	var tokenClaims JwtClaims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return JwtClaims{}, fmt.Errorf("invalid token claims")
	}
	app_id, ok := claims["app_id"].(float64)
	if !ok {
		return JwtClaims{}, fmt.Errorf("invalid app id in token")
	}

	tokenClaims.Email, ok = claims["email"].(string)
	if !ok {
		return JwtClaims{}, fmt.Errorf("invalid email in token")
	}
	uid, ok := claims["uid"].(float64)
	if !ok {
		return JwtClaims{}, fmt.Errorf("invalid user id in token")
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return JwtClaims{}, fmt.Errorf("invalid exp in token")
	}

	tokenClaims.App_id = int(app_id)
	tokenClaims.Exp = int64(exp)
	tokenClaims.Uid = int64(uid)

	if !token.Valid {
		return JwtClaims{}, fmt.Errorf("invalid token")
	}

	return tokenClaims, nil
}
