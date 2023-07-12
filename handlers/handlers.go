package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"time"

	"win_events/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

type Credentials struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type Handler struct {
	Client *mongo.Client
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)
	hashedPassword, _ := HashPassword(user.Password)
	user.Password = hashedPassword
	collection := h.Client.Database("win_events_db").Collection("users")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.InsertOne(ctx, user)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) AuthenticateUser(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	_ = json.NewDecoder(r.Body).Decode(&creds)

	collection := h.Client.Database("win_events_db").Collection("users")
	var user models.User
	err := collection.FindOne(context.Background(), bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if !CheckPasswordHash(creds.Password, user.Password) {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	token, err := GenerateJWT(creds.Email)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token})
}

func (h *Handler) CreateEventEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	_ = json.NewDecoder(r.Body).Decode(&event)
	collection := h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.InsertOne(ctx, event)
	json.NewEncoder(w).Encode(result)
}

func isEmptyValue(v interface{}) bool {
	switch x := v.(type) {
	case string:
		return x == ""
	case int:
		return x == 0
	case []string:
		return len(x) == 0
	case time.Time:
		return x.IsZero()
	default:
		return false
	}
}

func (h *Handler) UpdateEventEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	err := json.NewDecoder(r.Body).Decode(&event)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	params := mux.Vars(r)
	idStr, ok := params["id"]
	if !ok {
		http.Error(w, "Missing or invalid _id field", http.StatusBadRequest)
		return
	}

	id, _ := primitive.ObjectIDFromHex(idStr)

	update := bson.M{}
	structValue := reflect.ValueOf(event)
	typeOfEvent := structValue.Type()

	for i := 0; i < structValue.NumField(); i++ {
		fieldName := typeOfEvent.Field(i).Name
		fieldValue := structValue.Field(i).Interface()
		if !isEmptyValue(fieldValue) {
			update[fieldName] = fieldValue
		}
	}

	collection := h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, err := collection.UpdateOne(
		ctx,
		bson.M{"_id": id},
		bson.D{{"$set", update}},
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(result)
}

func (h *Handler) DeleteEventEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	_ = json.NewDecoder(r.Body).Decode(&event)
	collection := h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.DeleteOne(ctx, bson.M{"_id": event.ID})
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) GetAllEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	var events []models.Event
	collection := h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cursor, err := collection.Find(ctx, bson.M{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var event models.Event
		cursor.Decode(&event)
		events = append(events, event)
	}
	if err := cursor.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(events)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateJWT(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
	})

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
