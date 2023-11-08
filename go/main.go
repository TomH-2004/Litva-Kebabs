package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var store = sessions.NewCookieStore([]byte("your-secret-key"))

func main() {
	var err error
	db, err = sql.Open("mysql", "devuser:123456@tcp(127.0.0.1:3306)/kebabshop")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	r := mux.NewRouter()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("html/static"))))

	// Define a middleware to check if the user is authenticated
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "user-session")
			username, ok := session.Values["username"].(string)
			if !ok || username == "" {
				http.Redirect(w, r, "/", http.StatusSeeOther) // Redirect to login if not authenticated
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	r.Handle("/home", authMiddleware(http.HandlerFunc(homeHandler))).Methods("GET")
	r.Handle("/profile", authMiddleware(http.HandlerFunc(profileHandler))).Methods("GET")
	r.Handle("/order", authMiddleware(http.HandlerFunc(orderHandler))).Methods("GET")
	r.Handle("/restaurant", authMiddleware(http.HandlerFunc(restaurantHandler))).Methods("GET")
	r.Handle("/reviews", authMiddleware(http.HandlerFunc(reviewsHandler))).Methods("GET")

	// Handle the root path for login form and logic
	r.HandleFunc("/", loginHandler).Methods("GET")
	r.HandleFunc("/", loginPostHandler).Methods("POST")
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
	session, _ := store.Get(r, "user-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

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
	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedPassword string
	err := db.QueryRow("SELECT password FROM login WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		http.Redirect(w, r, "/login?error=2", http.StatusSeeOther)
		return
	}

	session, _ := store.Get(r, "user-session")
	session.Values["username"] = username
	session.Save(r, w)

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	newUsername := r.FormValue("newUsername")
	newPassword := r.FormValue("newPassword")
	email := r.FormValue("email")
	address := r.FormValue("address")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT INTO login (username, password, email, address) VALUES (?, ?, ?, ?)", newUsername, hashedPassword, email, address)
	if err != nil {
		http.Error(w, "Database insert error", http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "user-session")
	session.Values["username"] = newUsername
	session.Save(r, w)

	http.Redirect(w, r, "/home", http.StatusSeeOther)
}
