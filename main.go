package main

import (
	"github.com/Ivansergee/medods-test/database"
	"github.com/Ivansergee/medods-test/handlers"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"log"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	database.ConnectDB()
	defer database.DisconnectDB()

	app := fiber.New()
	app.Post("/token", handlers.TokenHandler)
	app.Post("/token/refresh", handlers.RefreshTokenHandler)

	app.Listen(":8000")
}
