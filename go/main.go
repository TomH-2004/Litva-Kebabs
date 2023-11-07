package main

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("html/static"))))

	// Define routes to handle URLs without the ".html" extension
	r.HandleFunc("/home", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/profile", profileHandler).Methods("GET")
	r.HandleFunc("/order", orderHandler).Methods("GET")
	r.HandleFunc("/restaurant", restaurantHandler).Methods("GET")
	r.HandleFunc("/reviews", reviewsHandler).Methods("GET")

	http.Handle("/", r)

	// Print a message indicating that the server is running
	fmt.Println("Server is listening on :8080")
	http.ListenAndServe(":8080", nil)
}

func renderTemplate(w http.ResponseWriter, tmpl string) {
	t, err := template.ParseFiles("../html/" + tmpl + ".html")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing home page")
	renderTemplate(w, "home")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing login page")
	renderTemplate(w, "login")
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing profile page")
	renderTemplate(w, "profile")
}

func orderHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing order page")
	renderTemplate(w, "order")
}

func restaurantHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing restaurant page")
	renderTemplate(w, "restaurant")
}

func reviewsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing reviews page")
	renderTemplate(w, "reviews")
}
