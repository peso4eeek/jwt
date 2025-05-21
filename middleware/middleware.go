package middleware

import (
	"fmt"
	"jwt/core"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

func JWTMiddleWare(next echo.HandlerFunc, secret string, appId int) echo.HandlerFunc {
	return func(c echo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")
		if tokenString == "" {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Missing token"})
		}
		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		claims := &core.JwtClaims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		})
		if err != nil || !token.Valid {
			return c.JSON(http.StatusUnauthorized, map[string]string{"message": "Invalid token"})
		}
		if claims.App_id != appId {
			return fmt.Errorf("Invalid app id in token: %w", err)
		}
		c.Set("uid", claims.Uid)
		c.Set("email", claims.Email)
		c.Set("app_id", claims.App_id)
		return next(c)
	}
}
