package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                  primitive.ObjectID   `bson:"_id,omitempty"`
	FirstName           string               `bson:"first_name"`
	LastName            string               `bson:"last_name"`
	ProfilePhoto        []byte               `bson:"profile_photo"`
	Email               string               `bson:"email"`
	Password            string               `bson:"password"` // This should be hashed, not plain text
	PhoneNum            string               `bson:"phone_num"`
	FavouriteOrganisers []primitive.ObjectID `bson:"favourite_organisers"`
	SavedEvents         []primitive.ObjectID `bson:"saved_events"`
}

type Organiser struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`
	Name           string             `bson:"name"`
	Type           string             `bson:"type"` // Society or Department
	Logo           []byte             `bson:"logo"`
	Description    string             `bson:"description"`
	Email          string             `bson:"email"`
	Password       string             `bson:"password"` // This should be hashed, not plain text
	PhoneNum       string             `bson:"phone_num"`
	Status         string             `bson:"status"`
	SocialMediaURL string             `bson:"social_media_url"`
}

type Event struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Title       string             `bson:"title"`
	URL         string             `bson:"url"` // Event URL/Webpage
	Photo       []byte             `bson:"photo"`
	Description string             `bson:"description"`
	Organiser   primitive.ObjectID `bson:"organiser"`
	Location    string             `bson:"location"`
	Time        string             `bson:"time"`
	Type        string             `bson:"type"`
	Metadata    map[string]string  `bson:"metadata"`
	IsVisible   bool               `bson:"is_visible"`
}
