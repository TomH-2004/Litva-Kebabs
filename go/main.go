package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
)

var db *sql.DB

func main() {
	var err error
	db, err = sql.Open("mysql", "devuser:123456@tcp(127.0.0.1:3306)/kebabshop")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("html/static"))))

	r.HandleFunc("/home", homeHandler).Methods("GET")
	r.HandleFunc("/login", loginHandler).Methods("GET")
	r.HandleFunc("/profile", profileHandler).Methods("GET")
	r.HandleFunc("/order", orderHandler).Methods("GET")
	r.HandleFunc("/restaurant", restaurantHandler).Methods("GET")
	r.HandleFunc("/reviews", reviewsHandler).Methods("GET")

	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/signup", signupHandler).Methods("POST")

	http.Handle("/", r)

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

func loginPostHandler(w http.ResponseWriter, r *http.Request) {

}

func signupHandler(w http.ResponseWriter, r *http.Request) {

	newUsername := r.FormValue("newUsername")
	newPassword := r.FormValue("newPassword")
	email := r.FormValue("email")
	address := r.FormValue("address")

	_, err := db.Exec("INSERT INTO login (username, password, email, address) VALUES (?, ?, ?, ?)", newUsername, newPassword, email, address)
	if err != nil {

		http.Redirect(w, r, "/signup", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}
