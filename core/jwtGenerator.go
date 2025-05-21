package core

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func NewAccessToken(userID int64, email string, appId int, appAccessSecret string, duration time.Duration) (accessToken string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = userID
	claims["email"] = email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = appId

	tokenString, err := token.SignedString([]byte(appAccessSecret))
	if err != nil {
		return "", fmt.Errorf("NewAccessToken failed with %w", err)
	}

	return tokenString, nil
}

func NewARefreshToken(userID int64, email string, appId int, appRefreshSecret string, duration time.Duration) (refreshToken string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)

	claims["uid"] = userID
	claims["email"] = email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = appId

	tokenString, err := token.SignedString([]byte(appRefreshSecret))
	if err != nil {
		return "", fmt.Errorf("NewAccessToken failed with %w", err)
	}

	return tokenString, nil
}
