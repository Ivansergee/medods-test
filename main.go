package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID               string
	RefreshTokenHash string
}

type TokenReq struct {
	ID string `json:"id"`
}

type TokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokenReq struct {
	ID           string `json:"id"`
	RefreshToken string `json:"refresh_token"`
}

var jwtSecretKey = []byte("secret-key")

var users = map[string]User{}

func GenerateTokens(sub string) (string, string, string, error) {
	payload := jwt.MapClaims{
		"sub": sub,
		"exp": time.Now().Add(time.Minute * 15).Unix(),
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	accessTokenStr, err := accessToken.SignedString(jwtSecretKey)

	if err != nil {
		return "", "", "", errors.New("jwt error")
	}

	refreshToken := make([]byte, 32)
	if _, err := rand.Read(refreshToken); err != nil {
		return "", "", "", errors.New("rand error")
	}
	refreshTokenStr := base64.StdEncoding.EncodeToString(refreshToken)
	refreshTokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshTokenStr), bcrypt.DefaultCost)
	if err != nil {
		return "", "", "", errors.New("bcrypt error")
	}

	return accessTokenStr, refreshTokenStr, string(refreshTokenHash), nil
}

func ConnectToDB() (*mongo.Client, error) {
	// Установите таймаут подключения в 10 секунд
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Создайте подключение к базе данных MongoDB
	client, err := mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	// Проверьте подключение к базе данных
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	log.Println("Connected to MongoDB!")
	return client, nil
}

func main() {
	users["foobar"] = User{ID: "foobar"}

	app := fiber.New()
	app.Post("/token", func(c *fiber.Ctx) error {
		req := TokenReq{}
		err := c.BodyParser(&req)
		if err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"message": "invalid json"})
		}

		user, ok := users[req.ID]
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
		}

		accessToken, refreshToken, refreshTokenHash, err := GenerateTokens(user.ID)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		user = User{
			ID:               user.ID,
			RefreshTokenHash: refreshTokenHash,
		}
		users[user.ID] = user
		res := TokenResp{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		return c.JSON(res)
	})
	app.Post("/token/refresh", func(c *fiber.Ctx) error {
		req := RefreshTokenReq{}
		err := c.BodyParser(&req)
		if err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"message": "invalid json"})
		}

		user, ok := users[req.ID]
		if !ok {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.RefreshTokenHash), []byte(req.RefreshToken))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid token"})
		}

		accessToken, refreshToken, refreshTokenHash, err := GenerateTokens(user.ID)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		user.RefreshTokenHash = refreshTokenHash
		users[req.ID] = user

		res := TokenResp{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		return c.JSON(res)

	})

	app.Listen(":8000")
}
