package database

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type User struct {
	ID               string `bson:"guid"`
	RefreshTokenHash string `bson:"refresh_token_hash"`
}

var db *mongo.Database

func ConnectDB() {
	clientOptions := options.Client().ApplyURI(os.Getenv("DB_URI"))
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	db = client.Database(os.Getenv("DB_NAME"))
}

func DisconnectDB() {
	if db != nil {
		db.Client().Disconnect(context.Background())
	}
}

func GetUser(guid string) (*User, error) {
	var user User
	collection := db.Collection(os.Getenv("DB_COLLECTION"))

	filter := bson.D{{"guid", guid}}
	err := collection.FindOne(context.Background(), filter).Decode(&user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func UpdateUser(guid string, refreshTokenHash string) error {
	collection := db.Collection(os.Getenv("DB_COLLECTION"))

	filter := bson.D{{"guid", guid}}
	update := bson.M{"$set": bson.M{"refresh_token_hash": refreshTokenHash}}
	_, err := collection.UpdateOne(context.Background(), filter, update)
	if err != nil {
		return err
	}
	return nil
}
