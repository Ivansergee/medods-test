package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID               string `bson:"guid"`
	RefreshTokenHash string `bson:"refresh_token_hash"`
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

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	clientOptions := options.Client().ApplyURI(os.Getenv("DB_URI"))
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database(os.Getenv("DB_NAME")).Collection(os.Getenv("DB_COLLECTION"))

	defer func() {
		if err = client.Disconnect(context.Background()); err != nil {
			log.Fatal(err)
		}
	}()

	app := fiber.New()
	app.Post("/token", func(c *fiber.Ctx) error {
		req := TokenReq{}
		err := c.BodyParser(&req)
		if err != nil {
			return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"message": "invalid json"})
		}

		var user User

		filter := bson.D{{"guid", req.ID}}
		err = collection.FindOne(context.Background(), filter).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
		}

		accessToken, err := GenAccess(user.ID)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		refreshToken, refreshTokenHash, err := GenRefresh()
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		update := bson.M{"$set": bson.M{"refresh_token_hash": refreshTokenHash}}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

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

		var user User

		filter := bson.D{{"guid", req.ID}}
		err = collection.FindOne(context.Background(), filter).Decode(&user)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
		}

		err = bcrypt.CompareHashAndPassword([]byte(user.RefreshTokenHash), []byte(req.RefreshToken))
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid token"})
		}

		accessToken, err := GenAccess(user.ID)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		refreshToken, refreshTokenHash, err := GenRefresh()
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		update := bson.M{"$set": bson.M{"refresh_token_hash": refreshTokenHash}}
		_, err = collection.UpdateOne(context.Background(), filter, update)
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}

		res := TokenResp{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}

		return c.JSON(res)

	})

	app.Listen(":8000")
}
