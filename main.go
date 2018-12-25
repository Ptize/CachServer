package main

import (
	"io"
	"time"
	"sync"
	"strconv"
	"net/http"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	"github.com/golang/glog"
	"github.com/pkg/errors"
	"github.com/gocraft/web"
	_ "github.com/lib/pq"
)


var (
	db    *sql.DB
	lock  sync.RWMutex
	cache = make(map[string]string, 100)
)

type Context struct {
	err error
}

func (c *Context) GetDocument(id string) string {
	lock.RLock()
	defer lock.RUnlock()
	return cache[id]
}

func (c *Context) SetDocument(id, text string) {
	lock.Lock()
	defer lock.Unlock()
	cache[id] = text
}

func (c *Context) ReadDocument(id string) string {
	var err error
	var intID int
	var data []byte

	intID, err = strconv.Atoi(id)
	if err != nil {
		c.err = errors.Wrap(err, "converting doc ID")
		return ""
	}

	doc := c.SelectDoc(intID)
	if c.err != nil {
		return ""
	}
	if doc == nil {
		return ""
	}

	data, err = json.Marshal(doc)
	if err != nil {
		c.err = errors.Wrap(err, "marshaling doc")
		return ""
	}

	return string(data)
}

func (c *Context) Docs(rw web.ResponseWriter, req *web.Request) {

	var err error
	var data []byte

	docs := c.Select()
	if c.err != nil {
		return
	}

	data, err = json.Marshal(docs)
	if err != nil {
		c.err = errors.Wrap(err, "marshaling docs")
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.Write(data)
}

func (c *Context) Document(rw web.ResponseWriter, req *web.Request) {
	var text string

	id := req.PathParams["doc_id"]

	args := req.URL.Query()
	if args.Get("force") != "1" {
		text = c.GetDocument(id)
	}

	if text == "" {
		glog.Info("cache miss")
		text = c.ReadDocument(id)
		if c.err != nil {
			return
		}
		c.SetDocument(id, text)
	}

	if text == "" {
		rw.WriteHeader(http.StatusNotFound)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	io.WriteString(rw, text)
}

type Doc struct {
	ID   int
	Name string
	Text string
}

func (c *Context) Select() (docs []*Doc) {

	docs = make([]*Doc, 0, 100)

	rows, err := db.Query("select id, name, data from docs;")
	if err != nil {
		c.err = errors.Wrap(err, "selecting docs")
		return
	}
	defer rows.Close()

	for rows.Next() {

		doc := new(Doc)
		err = rows.Scan(&doc.ID, &doc.Name, &doc.Text)
		if err != nil {
			c.err = errors.Wrap(err, "scanning docs")
			return
		}

		docs = append(docs, doc)

	}

	if err = rows.Err(); err != nil {
		c.err = errors.Wrap(err, "finalizing doc")
		return
	}

	return
}

func (c *Context) SelectDoc(id int) (doc *Doc) {

	rows, err := db.Query(`select 
			id,
			name,
			data
		from docs 
		where 
			id = $1;
	`, id)
	if err != nil {
		c.err = errors.Wrap(err, "selecting doc")
		return
	}
	defer rows.Close()

	if rows.Next() {

		doc = new(Doc)
		err = rows.Scan(&doc.ID, &doc.Name, &doc.Text)
		if err != nil {
			c.err = errors.Wrap(err, "scanning doc")
			return
		}

	}

	if err = rows.Err(); err != nil {
		c.err = errors.Wrap(err, "finalizing doc")
		return
	}

	return
}

func (c *Context) Errors(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {

	next(rw, req)

	if c.err != nil {
		glog.Errorf("Ошибка: %+v", c.err)
		rw.WriteHeader(http.StatusInternalServerError)
	}
}

func (c *Context) Logs(rw web.ResponseWriter, req *web.Request, next web.NextMiddlewareFunc) {

	start := time.Now()

	next(rw, req)

	glog.Infof("[ %s ][ %s ] %s", time.Since(start), req.Method, req.URL)
}

func main(){

	var err error

	connStr := "user=postgres password=superuser dbname=docs sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	router := web.New(Context{})
	router.Middleware((*Context).Logs)
	router.Middleware((*Context).Errors)
	router.Get("/docs/", (*Context).Docs)
	router.Get("/docs/:doc_id/", (*Context).Document)

	http.Handle("/", router)

	fmt.Println("Server is listening...")
	if db, err = sql.Open("postgres", connStr); err != nil {
		glog.Fatal(err)
	}

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
	if err = http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}