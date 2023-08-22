package tokens

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecretKey = []byte(os.Getenv("SECRET_KEY"))

func GenAccess(sub string) (string, error) {
	payload := jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	accessTokenStr, err := accessToken.SignedString(jwtSecretKey)
	if err != nil {
		return "", errors.New("jwt error")
	}

	return accessTokenStr, nil
}

func GenRefresh() (string, string, error) {
	refreshToken := make([]byte, 32)
	if _, err := rand.Read(refreshToken); err != nil {
		return "", "", errors.New("rand error")
	}

	refreshTokenStr := base64.StdEncoding.EncodeToString(refreshToken)
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshTokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", errors.New("bcrypt error")
	}

	return refreshTokenStr, string(refreshTokenHash), nil
}
