package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"win_events/handlers"

	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
	fmt.Println("Starting the application...")
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	clientOptions := options.Client().ApplyURI("mongodb://localhost:27017")
	client, _ := mongo.Connect(ctx, clientOptions)

	router := mux.NewRouter()
	handler := &handlers.Handler{
		Client: client,
	}

	router.HandleFunc("/users", handler.CreateUser).Methods("POST")
	router.HandleFunc("/users/auth", handler.AuthenticateUser).Methods("POST")

	// Subrouter for endpoints that require JWT auth
	r := router.PathPrefix("/event").Subrouter()
	// r.Use(middleware.AuthMiddleware)
	r.HandleFunc("", handler.CreateEventEndpoint).Methods("POST")
	r.HandleFunc("", handler.GetAllEventsEndpoint).Methods("GET")
	r.HandleFunc("/{id}", handler.UpdateEventEndpoint).Methods("PUT")
	r.HandleFunc("/{id}", handler.DeleteEventEndpoint).Methods("DELETE")

	http.ListenAndServe(":12345", router)
}
