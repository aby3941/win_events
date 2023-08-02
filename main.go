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
	router.HandleFunc("/user/signup", handler.CreateUser).Methods("POST")
	router.HandleFunc("/user/login", handler.AuthenticateUser).Methods("POST")

	// Subrouter for endpoints that require JWT auth
	r := router.PathPrefix("/organiser").Subrouter()
	r.Use(middleware.AuthMiddleware)
	r.HandleFunc("/event", handler.CreateEventEndpoint).Methods("POST")
	r.HandleFunc("/event", handler.GetAllOrganiserEventsEndpoint).Methods("GET")
	r.HandleFunc("/event/{id}", handler.UpdateEventEndpoint).Methods("PUT")
	r.HandleFunc("/event/visibility/{id}", handler.UpdateEventVisibilityEndpoint).Methods("PUT")
	r.HandleFunc("/event/{id}", handler.DeleteEventEndpoint).Methods("DELETE")
	r.HandleFunc("/event/filter", handler.FilterOrganiserEventsEndpoint).Methods("GET")
	r.HandleFunc("/details", handler.GetOrganiserDetailsEndpoint).Methods("GET")
	r.HandleFunc("/details/{id}", handler.UpdateOrganiserDetailsEndpoint).Methods("PUT")
	r.HandleFunc("/event/search/{searchQuery}", handler.SearchOrganiserEventsEndpoint).Methods("GET")

	r_user := router.PathPrefix("/user").Subrouter()
	r_user.Use(middleware.AuthMiddleware)
	r_user.HandleFunc("/event", handler.GetAllEventsEndpoint).Methods("GET")
	r_user.HandleFunc("/event/saved", handler.GetAllSavedEventsEndpoint).Methods("GET")
	r_user.HandleFunc("/event/fav", handler.GetAllFavouriteOrgEventsEndpoint).Methods("GET")
	r_user.HandleFunc("/event/filter", handler.FilterEventsEndpoint).Methods("GET")
	r_user.HandleFunc("/details", handler.GetUserDetailsEndpoint).Methods("GET")
	r_user.HandleFunc("/details/{id}", handler.UpdateUserDetailsEndpoint).Methods("PUT")
	r_user.HandleFunc("/event/search/{searchQuery}", handler.SearchEventsEndpoint).Methods("GET")
	r_user.HandleFunc("/organisers", handler.GetAllOrganisersEndpoint).Methods("GET")
	http.ListenAndServe(":9000", router)
}
