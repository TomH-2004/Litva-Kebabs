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

	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, "user-session")
			username, ok := session.Values["username"].(string)
			if !ok || username == "" {
				http.Redirect(w, r, "/", http.StatusSeeOther)
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
	r.Handle("/signout", authMiddleware(http.HandlerFunc(signoutHandler))).Methods("GET")
	r.Handle("/editdetails", authMiddleware(http.HandlerFunc(editDetailsHandler))).Methods("POST")
	r.Handle("/changepassword", authMiddleware(http.HandlerFunc(changePasswordHandler))).Methods("POST")
	r.Handle("/updateprofile", authMiddleware(http.HandlerFunc(updateProfileHandler))).Methods("POST")
	r.Handle("/signoutafterupdate", authMiddleware(http.HandlerFunc(signoutHandlerAfterUpdate))).Methods("GET")

	r.HandleFunc("/", loginHandler).Methods("GET")
	r.HandleFunc("/", loginPostHandler).Methods("POST")
	r.HandleFunc("/signup", signupHandler).Methods("POST")

	http.Handle("/", r)

	fmt.Println("Server is listening on :8080")
	http.ListenAndServe(":8080", nil)
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, err := template.ParseFiles("../html/" + tmpl + ".html")

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = t.Execute(w, data)
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
	renderTemplate(w, "home", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing login page")
	renderTemplate(w, "login", nil)
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {

	session, _ := store.Get(r, "user-session")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var userData struct {
		Username string
		Email    string
		Address  string
	}
	err := db.QueryRow("SELECT username, email, address FROM login WHERE username = ?", username).Scan(&userData.Username, &userData.Email, &userData.Address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "profile", userData)
}

func orderHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing order page")
	renderTemplate(w, "order", nil)
}

func restaurantHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing restaurant page")
	renderTemplate(w, "restaurant", nil)
}

func reviewsHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Accessing reviews page")
	renderTemplate(w, "reviews", nil)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	var storedPassword string
	err := db.QueryRow("SELECT password FROM login WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {
		http.Redirect(w, r, "/?error=1", http.StatusSeeOther)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		http.Redirect(w, r, "/?error=2", http.StatusSeeOther)
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

func editDetailsHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	newUsername := r.FormValue("newUsername")
	newEmail := r.FormValue("newEmail")
	newAddress := r.FormValue("newAddress")

	_, err := db.Exec("UPDATE login SET username=?, email=?, address=? WHERE username=?", newUsername, newEmail, newAddress, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {

		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	currentPassword := r.FormValue("currentPassword")
	newPassword := r.FormValue("newPassword")

	var storedPassword string
	err := db.QueryRow("SELECT password FROM login WHERE username = ?", username).Scan(&storedPassword)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(currentPassword))
	if err != nil {

		http.Error(w, "Current password is incorrect", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {

		http.Error(w, "Password hashing error", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE login SET password=? WHERE username=?", hashedPassword, username)
	if err != nil {

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("true"))
}

func updateProfileHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodPost {
		newUsername := r.FormValue("newUsername")
		newEmail := r.FormValue("newEmail")
		newAddress := r.FormValue("newAddress")

		_, err := db.Exec("UPDATE login SET username = ?, email = ?, address = ? WHERE username = ?", newUsername, newEmail, newAddress, username)
		if err != nil {

			fmt.Println("Error updating user data:", err)
			http.Error(w, "Failed to update profile", http.StatusInternalServerError)
			return
		}

		fmt.Println("User profile updated successfully")

		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func signoutHandlerAfterUpdate(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "user-session")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
