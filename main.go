package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/CossackPyra/pyraconv"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var c [5]ContactDetails
var (
	// key must be 16, 24 or 32 bytes long (AES-128, AES-192 or AES-256)
	key   = []byte("super-secret-key")
	store = sessions.NewCookieStore(key)
)

type ViewData struct {
	Title string
	Users []User
}

type User struct {
	Name string
	Age  int64
	URL  string
}

type ContactDetails struct {
	id   string `json:"id"`
	name string `json:"name"`
	age  string `json:"age"`
}

func secret(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Check if user is authenticated
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Print secret message
	fmt.Fprintln(w, "The cake is a lie!")
}

func login(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Authentication goes here
	// ...

	// Set user as authenticated
	session.Values["authenticated"] = true
	session.Save(r, w)
}

func logout(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "cookie-name")

	// Revoke users authentication
	session.Values["authenticated"] = false
	session.Save(r, w)
}

type Middleware func(http.HandlerFunc) http.HandlerFunc

// Logging logs all requests with its path and the time it took to process
func Logging() Middleware {

	// Create a new Middleware
	return func(f http.HandlerFunc) http.HandlerFunc {

		// Define the http.HandlerFunc
		return func(w http.ResponseWriter, r *http.Request) {

			// Do middleware things
			start := time.Now()
			defer func() { log.Println(r.URL.Path, time.Since(start)) }()

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

// Method ensures that url can only be requested with a specific method, else returns a 400 Bad Request
func Method(m string) Middleware {

	// Create a new Middleware
	return func(f http.HandlerFunc) http.HandlerFunc {

		// Define the http.HandlerFunc
		return func(w http.ResponseWriter, r *http.Request) {

			// Do middleware things
			if r.Method != m {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			// Call the next middleware/handler in chain
			f(w, r)
		}
	}
}

// Chain applies middlewares to a http.HandlerFunc
func Chain(f http.HandlerFunc, middlewares ...Middleware) http.HandlerFunc {
	for _, m := range middlewares {
		f = m(f)
	}
	return f
}

func Hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "hello world")
}

func UsingTempl(w http.ResponseWriter, r *http.Request) {
	/*var Users1 [5]User

	for i, _ := range Users1 {
		User.Name= c[i].name
		User.Age= pyraconv.ToInt64(c[i].age)
		User.URL= "URLI1"}
	}*/

	data := ViewData{
		Title: "Users List",
		Users: []User{
			User{Name: c[0].name, Age: pyraconv.ToInt64(c[0].age), URL: "URLI1"},
			User{Name: c[1].name, Age: pyraconv.ToInt64(c[1].age), URL: "URLI2"},
			User{Name: c[2].name, Age: pyraconv.ToInt64(c[2].age), URL: "URLI3"},
		},
	}
	tmpl, _ := template.ParseFiles("templates/index.html")
	tmpl.Execute(w, data)
}

func UsingTempl2(w http.ResponseWriter, r *http.Request) {

	password := "secret"
	hash, _ := HashPassword(password) // ignore error for the sake of simplicity

	fmt.Println("Password:", password)
	fmt.Println("Hash:    ", hash)

	match := CheckPasswordHash(password, hash)
	fmt.Println("Match:   ", match)

	if r.Method != http.MethodPost {
		tmpl := template.Must(template.ParseFiles("templates/templForm.html"))

		tmpl.Execute(w, nil)
		return
	}

	tmpl := template.Must(template.ParseFiles("templates/templForm.html"))

	details := ContactDetails{
		id:   r.FormValue("id"),
		name: r.FormValue("name"),
		age:  r.FormValue("age"),
	}
	connStr := "user=postgres password=superuser dbname=Names sslmode=disable" //"postgres://postgres:psql@127.0.0.1:5433/Names?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	result, err := db.Exec("insert into Names (id, name, age) values ( $1, $2, $3)", //text
		pyraconv.ToInt64(details.id), details.name, pyraconv.ToInt64(details.age))
	if err != nil {
		panic(err)
	}

	fmt.Println(result.LastInsertId()) // не поддерживается
	fmt.Println(result.RowsAffected()) // количество добавленных строк
	// do something with details
	_ = details

	tmpl.Execute(w, struct{ Success bool }{true})
}

func productsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	cat := vars["category"]
	response := fmt.Sprintf("Product category=%s id=%s", cat, id)
	fmt.Fprint(w, response)
}

func articlesHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	response := fmt.Sprintf("id=%s", id)
	fmt.Fprint(w, response)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	connStr := "user=postgres password=superuser dbname=Names sslmode=disable" //"postgres://postgres:psql@127.0.0.1:5433/Names?sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	result, err := db.Query("SELECT id, name, age FROM public.names;")
	if err != nil {
		panic(err)
	}
	defer result.Close()
	contactDetails := []ContactDetails{}

	for result.Next() {
		p := ContactDetails{}
		err := result.Scan(&p.id, &p.name, &p.age)
		if err != nil {
			fmt.Println(err)
			continue
		}
		contactDetails = append(contactDetails, p)
	}
	for i, p := range contactDetails {
		fmt.Println(p.id, p.name, p.age)
		c[i].id = p.id
		c[i].name = p.name
		c[i].age = p.age
	}

	response := fmt.Sprintf("%s", contactDetails)
	fmt.Fprint(w, response)
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Define our struct
/*type authenticationMiddleware struct {
	tokenUsers map[string]string
}

// Initialize it somewhere
func (amw *authenticationMiddleware) Populate() {
	amw.tokenUsers["00000000"] = "user0"
	amw.tokenUsers["aaaaaaaa"] = "userA"
	amw.tokenUsers["05f717e5"] = "randomUser"
	amw.tokenUsers["deadbeef"] = "user0"
}

// Middleware function, which will be called for each request
func (amw *authenticationMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Session-Token")

		if user, found := amw.tokenUsers[token]; found {
			// We found the token in our map
			log.Printf("Authenticated user %s\n", user)
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Forbidden", http.StatusForbidden)
		}
	})
}*/

func main() {

	var err error

	router := mux.NewRouter()
	router.HandleFunc("/products/{category}/{id:[0-9]+}", productsHandler)
	router.HandleFunc("/products/{id:[0-9]+}", articlesHandler)
	router.HandleFunc("/articles/{id:[0-9]+}", articlesHandler)
	router.HandleFunc("/", Chain(indexHandler, Method("GET"), Logging()))
	router.HandleFunc("/templetes", Chain(UsingTempl2, Logging()))
	router.HandleFunc("/templete", Chain(UsingTempl, Method("GET"), Logging()))
	router.HandleFunc("/newmethod", Chain(Hello, Method("GET"), Logging()))
	router.HandleFunc("/secret", Chain(secret, Method("GET"), Logging()))
	router.HandleFunc("/login", Chain(login, Method("GET"), Logging()))
	router.HandleFunc("/logout", Chain(logout, Method("GET"), Logging()))

	/*
		amw := authenticationMiddleware{make(map[string]string)}
		amw.tokenUsers["00000000"] = "user0"
		amw.tokenUsers["aaaaaaaa"] = "userA"
		amw.tokenUsers["05f717e5"] = "randomUser"
		amw.tokenUsers["deadbeef"] = "user0"

		router.Use(amw.Middleware)
	*/

	http.Handle("/", router)

	fmt.Println("Server is listening...")
	if err = http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}

}
