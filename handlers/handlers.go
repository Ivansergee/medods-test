package handlers

import (
	"github.com/Ivansergee/medods-test/database"
	"github.com/Ivansergee/medods-test/utils"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
)

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

func TokenHandler(c *fiber.Ctx) error {
	req := TokenReq{}
	err := c.BodyParser(&req)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"message": "invalid json"})
	}

	user, err := database.GetUser(req.ID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
	}

	accessToken, err := utils.GenAccess(user.ID)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	refreshToken, refreshTokenHash, err := utils.GenRefresh()
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	err = database.UpdateUser(req.ID, refreshTokenHash)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	res := TokenResp{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return c.JSON(res)
}

func RefreshTokenHandler(c *fiber.Ctx) error {
	req := RefreshTokenReq{}
	err := c.BodyParser(&req)
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"message": "invalid json"})
	}

	user, err := database.GetUser(req.ID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid credentials"})
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.RefreshTokenHash), []byte(req.RefreshToken))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"message": "invalid token"})
	}

	accessToken, err := utils.GenAccess(user.ID)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	refreshToken, refreshTokenHash, err := utils.GenRefresh()
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	err = database.UpdateUser(req.ID, refreshTokenHash)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	res := TokenResp{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	return c.JSON(res)

}
