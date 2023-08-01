package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"win_events/models"

	"github.com/golang-jwt/jwt/v5"
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

func (h *Handler) CreateOrganiser(w http.ResponseWriter, r *http.Request) {
	var user models.Organiser
	_ = json.NewDecoder(r.Body).Decode(&user)
	hashedPassword, _ := HashPassword(user.Password)
	user.Password = hashedPassword
	collection := h.Client.Database("win_events_db").Collection("organisers")
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

func (h *Handler) AuthenticateOrganiser(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	_ = json.NewDecoder(r.Body).Decode(&creds)

	collection := h.Client.Database("win_events_db").Collection("organisers")
	var user models.Organiser
	err := collection.FindOne(context.Background(), bson.M{"email": creds.Email}).Decode(&user)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusNotFound)
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

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedOrganizer models.Organiser

	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"_id": event.Organiser}).Decode(&requestedOrganizer)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedOrganizer.Email {
		http.Error(w, "Logged-in user is not authorized to create this event", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.InsertOne(ctx, event)
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) UpdateEventEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	_ = json.NewDecoder(r.Body).Decode(&event)

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedOrganizer models.Organiser

	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"_id": event.Organiser}).Decode(&requestedOrganizer)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedOrganizer.Email {
		http.Error(w, "Logged-in user is not authorized to edit this event", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	updateFields := bson.D{}

	if event.Title != "" {
		updateFields = append(updateFields, bson.E{Key: "title", Value: event.Title})
	}
	if event.URL != "" {
		updateFields = append(updateFields, bson.E{Key: "url", Value: event.URL})
	}
	if len(event.Photo) > 0 {
		updateFields = append(updateFields, bson.E{Key: "photo", Value: event.Photo})
	}
	if event.Description != "" {
		updateFields = append(updateFields, bson.E{Key: "description", Value: event.Description})
	}
	if event.Location != "" {
		updateFields = append(updateFields, bson.E{Key: "location", Value: event.Location})
	}
	if event.Time != "" {
		updateFields = append(updateFields, bson.E{Key: "time", Value: event.Time})
	}
	if event.Type != "" {
		updateFields = append(updateFields, bson.E{Key: "type", Value: event.Type})
	}
	if event.Metadata != nil {
		updateFields = append(updateFields, bson.E{Key: "metadata", Value: event.Metadata})
	}

	// Perform the update operation with the constructed updateFields.
	update := bson.D{{Key: "$set", Value: updateFields}}
	result, _ := collection.UpdateOne(ctx, bson.M{"_id": event.ID}, update)

	json.NewEncoder(w).Encode(result)
}

func (h *Handler) UpdateEventVisibilityEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	_ = json.NewDecoder(r.Body).Decode(&event)

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedOrganizer models.Organiser

	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"_id": event.Organiser}).Decode(&requestedOrganizer)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedOrganizer.Email {
		http.Error(w, "Logged-in user is not authorized to edit this event", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	updateFields := bson.D{}

	updateFields = append(updateFields, bson.E{Key: "is_visible", Value: event.IsVisible})

	// Perform the update operation with the constructed updateFields.
	update := bson.D{{Key: "$set", Value: updateFields}}
	result, _ := collection.UpdateOne(ctx, bson.M{"_id": event.ID}, update)

	json.NewEncoder(w).Encode(result)
}

func (h *Handler) DeleteEventEndpoint(w http.ResponseWriter, r *http.Request) {
	var event models.Event
	_ = json.NewDecoder(r.Body).Decode(&event)

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedOrganizer models.Organiser

	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"_id": event.Organiser}).Decode(&requestedOrganizer)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedOrganizer.Email {
		http.Error(w, "Logged-in user is not authorized to delete this event", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	result, _ := collection.DeleteOne(ctx, bson.M{"_id": event.ID})
	json.NewEncoder(w).Encode(result)
}

func (h *Handler) GetAllOrganiserEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	var events []models.Event

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var organiser models.Organiser
	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&organiser)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cursor, err := collection.Find(ctx, bson.M{"organiser": organiser.ID})
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
	w.Header().Set("Content-Type", "application/json")
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

func (h *Handler) SearchOrganiserEventsEndpoint(w http.ResponseWriter, r *http.Request) {

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var organiser models.Organiser
	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&organiser)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}

	query := bson.M{}

	params := r.URL.Query()
	for key, values := range params {
		switch key {
		case "title":
			query["title"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "organiser":
			query["organiser"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "location":
			query["location"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "type":
			query["type"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		}
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	cur, _ := collection.Find(ctx, query)

	var events []models.Event
	for cur.Next(ctx) {
		var result models.Event
		err := cur.Decode(&result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if result.Organiser == organiser.ID {
			events = append(events, result)
		}
	}

	if err := cur.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cur.Close(ctx)

	json.NewEncoder(w).Encode(events)
}

func (h *Handler) GetOrganiserDetailsEndpoint(w http.ResponseWriter, r *http.Request) {

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var organiser models.Organiser
	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&organiser)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}

	err = json.NewEncoder(w).Encode(organiser)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) GetUserDetailsEndpoint(w http.ResponseWriter, r *http.Request) {

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var user models.User
	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	err = json.NewEncoder(w).Encode(user)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func (h *Handler) UpdateUserDetailsEndpoint(w http.ResponseWriter, r *http.Request) {
	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedUser models.User

	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"_id": user.ID}).Decode(&requestedUser)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedUser.Email {
		http.Error(w, "Logged-in user is not authorized to edit this user", http.StatusUnauthorized)
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	updateFields := bson.D{}

	if user.FirstName != "" {
		updateFields = append(updateFields, bson.E{Key: "first_name", Value: user.FirstName})
	}
	if user.LastName != "" {
		updateFields = append(updateFields, bson.E{Key: "last_name", Value: user.LastName})
	}
	if len(user.ProfilePhoto) > 0 {
		updateFields = append(updateFields, bson.E{Key: "profile_photo", Value: user.ProfilePhoto})
	}
	if user.Password != "" {
		updateFields = append(updateFields, bson.E{Key: "password", Value: user.Password})
	}
	if user.PhoneNum != "" {
		updateFields = append(updateFields, bson.E{Key: "phone_num", Value: user.PhoneNum})
	}
	if user.FavouriteOrganisers != nil {
		updateFields = append(updateFields, bson.E{Key: "favourite_organisers", Value: user.FavouriteOrganisers})
	}
	if user.SavedEvents != nil {
		updateFields = append(updateFields, bson.E{Key: "saved_events", Value: user.SavedEvents})
	}

	// Perform the update operation with the constructed updateFields.
	update := bson.D{{Key: "$set", Value: updateFields}}
	result, _ := collection.UpdateOne(ctx, bson.M{"_id": user.ID}, update)

	json.NewEncoder(w).Encode(result)
}

func (h *Handler) UpdateOrganiserDetailsEndpoint(w http.ResponseWriter, r *http.Request) {
	var user models.Organiser
	_ = json.NewDecoder(r.Body).Decode(&user)

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var requestedUser models.User

	collection := h.Client.Database("win_events_db").Collection("organisers")
	err := collection.FindOne(context.Background(), bson.M{"_id": user.ID}).Decode(&requestedUser)
	if err != nil {
		http.Error(w, "Organiser not found", http.StatusUnauthorized)
		return
	}
	if userEmail != requestedUser.Email {
		http.Error(w, "Logged-in user is not authorized to edit this organiser", http.StatusUnauthorized)
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	updateFields := bson.D{}

	if user.Name != "" {
		updateFields = append(updateFields, bson.E{Key: "name", Value: user.Name})
	}

	if user.Description != "" {
		updateFields = append(updateFields, bson.E{Key: "description", Value: user.Description})
	}

	if len(user.Logo) > 0 {
		updateFields = append(updateFields, bson.E{Key: "logo", Value: user.Logo})
	}
	if user.Password != "" {
		updateFields = append(updateFields, bson.E{Key: "password", Value: user.Password})
	}
	if user.PhoneNum != "" {
		updateFields = append(updateFields, bson.E{Key: "phone_num", Value: user.PhoneNum})
	}
	if user.SocialMediaURL != "" {
		updateFields = append(updateFields, bson.E{Key: "social_media_url", Value: user.SocialMediaURL})
	}

	// Perform the update operation with the constructed updateFields.
	update := bson.D{{Key: "$set", Value: updateFields}}
	result, _ := collection.UpdateOne(ctx, bson.M{"_id": user.ID}, update)

	json.NewEncoder(w).Encode(result)
}

func (h *Handler) GetAllEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	var events []models.Event

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var user models.User
	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	collection = h.Client.Database("win_events_db").Collection("events")
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (h *Handler) GetAllSavedEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	var events []models.Event

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var user models.User
	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	var eventIDs []primitive.ObjectID
	if user.SavedEvents != nil && len(user.SavedEvents) > 0 {
		eventIDs = user.SavedEvents
	}
	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.M{
		"_id": bson.M{
			"$in": eventIDs,
		},
	}
	cursor, err := collection.Find(ctx, filter)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (h *Handler) GetAllFavouriteOrgEventsEndpoint(w http.ResponseWriter, r *http.Request) {
	var events []models.Event

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var user models.User
	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	var organiserIDs []primitive.ObjectID
	if user.FavouriteOrganisers != nil && len(user.FavouriteOrganisers) > 0 {
		organiserIDs = user.FavouriteOrganisers
	}
	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.M{
		"organiser": bson.M{
			"$in": organiserIDs,
		},
	}
	cursor, err := collection.Find(ctx, filter)
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(events)
}

func (h *Handler) SearchEventsEndpoint(w http.ResponseWriter, r *http.Request) {

	// Extract user information from the JWT claims
	claims, ok := r.Context().Value("props").(jwt.MapClaims)
	if !ok {
		http.Error(w, "Invalid JWT claims", http.StatusUnauthorized)
		return
	}

	userEmail, ok := claims["email"].(string)
	if !ok {
		http.Error(w, "Invalid user email in JWT claims", http.StatusUnauthorized)
		return
	}
	var user models.Organiser
	collection := h.Client.Database("win_events_db").Collection("users")
	err := collection.FindOne(context.Background(), bson.M{"email": userEmail}).Decode(&user)
	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	query := bson.M{}

	params := r.URL.Query()
	for key, values := range params {
		switch key {
		case "title":
			query["title"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "organiser":
			query["organiser"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "location":
			query["location"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		case "type":
			query["type"] = bson.M{"$regex": primitive.Regex{Pattern: values[0], Options: "i"}}
		}
	}

	collection = h.Client.Database("win_events_db").Collection("events")
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	cur, _ := collection.Find(ctx, query)

	var events []models.Event
	for cur.Next(ctx) {
		var result models.Event
		err := cur.Decode(&result)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		events = append(events, result)
	}

	if err := cur.Err(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cur.Close(ctx)

	json.NewEncoder(w).Encode(events)
}
