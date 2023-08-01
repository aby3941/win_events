package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"win_events/handlers"
	"win_events/middleware"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

func main() {
	fmt.Println("Starting the application...")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, _ := mongo.Connect(ctx, clientOptions)

	router := mux.NewRouter()
	handler := &handlers.Handler{
		Client: client,
	}

	router.Use(enableCORS)

	router.HandleFunc("/organiser/signup", handler.CreateOrganiser).Methods("POST")
	router.HandleFunc("/organiser/login", handler.AuthenticateOrganiser).Methods("POST")

	// Subrouter for endpoints that require JWT auth
	r := router.PathPrefix("/organiser").Subrouter()
	r.Use(middleware.AuthMiddleware)
	r.HandleFunc("/event", handler.CreateEventEndpoint).Methods("POST")
	r.HandleFunc("/event", handler.GetAllOrganiserEventsEndpoint).Methods("GET")
	r.HandleFunc("/event/{id}", handler.UpdateEventEndpoint).Methods("PUT")
	r.HandleFunc("/event/{id}", handler.DeleteEventEndpoint).Methods("DELETE")
	r.HandleFunc("/event/search", handler.SearchOrganiserEventsEndpoint).Methods("GET")
	r.HandleFunc("/details", handler.GetOrganiserDetails).Methods("GET")
	http.ListenAndServe(":9000", router)
}
