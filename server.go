package main

import "encoding/json"
import "io/ioutil"
import "net/http"

import "github.com/codegangsta/martini"
import "code.google.com/p/go.crypto/bcrypt"
import random "github.com/dustin/randbo"
import jwt "github.com/dgrijalva/jwt-go"
import uuid "github.com/nu7hatch/gouuid"

type App struct {
  Id        string
  Name      string
  Key       []byte
  Users     []User
}

type User struct {
  Email     string
  Password  []byte
}

var apps = []App{}

func main() {
	m := martini.Classic()
	m.Use(BodyHandler())
	m.Post("/v1/apps", CreateApp)
	m.Post("/v1/:app/login", LoginUser)
	m.Post("/v1/:app/users", CreateUser)
	m.Run()
}

type Body interface {
  Unmarshal(interface{})
}

func BodyHandler() martini.Handler {
  return func(req *http.Request, c martini.Context) {
    c.MapTo(&body{req}, (*Body)(nil))
  }
}

type body struct {
  req *http.Request
}

func (b *body) Unmarshal(result interface{}) {
  bod, _ := ioutil.ReadAll(b.req.Body)
  json.Unmarshal(bod, &result)
}

func CreateApp(body Body) (int, string) {
  type CreateAppRequest struct {
    Name    string
  }

  var data CreateAppRequest
  body.Unmarshal(&data)

  uuid, err := uuid.NewV4()
  if err != nil {
    return 500, "Error generating uuid"
  }

  id := uuid.String()

  key := make([]byte, 16)
  _, err = random.New().Read(key)

  if err != nil {
    return 500, "Error generating key"
  }

  apps = append(apps, App{id, data.Name, key, []User{}})

  return 201, string(key)
}

func CreateUser(params martini.Params, b Body) (int, string) {
  type CreateUserRequest struct {
    Email     string
    Password  string
  }

  var data CreateUserRequest
  b.Unmarshal(&data)

  if data.Password == "" {
    return 400, "Password required"
  }

  hash, err := bcrypt.GenerateFromPassword([]byte(data.Password), 10)
  if err != nil {
    return 500, "Error generating password hash"
  }

  app := findApp(params["app"])
  if app.Id == "" {
    return 404, "Application not found"
  }
  app.Users= append(app.Users, User{data.Email, hash})

  return 201, "Created"
}

type LoginRequest struct {
  Email     string
  Password  string
}

func LoginUser(params martini.Params, body Body) (int, string) {
  var data LoginRequest
  body.Unmarshal(&data)

  if data.Password == "" {
    return 400, "Password is required"
  }

  app := findApp(params["app"])
  if app.Id == "" {
    return 404, "Application not found"
  }

  for _, user := range app.Users {
    if user.Email == data.Email {
      return checkPasswordAndGenerateToken(app, user, data)
    }
  }

  return 401, "Not authorized"
}

func checkPasswordAndGenerateToken(app App, user User, req LoginRequest) (int, string) {
  if err := bcrypt.CompareHashAndPassword(user.Password, []byte(req.Password)); err != nil {
    return 401, "Password does not match"
  }

  token := jwt.New(jwt.GetSigningMethod("HS256"))
  token.Claims["id"] = 1
  tokenString, err := token.SignedString(app.Key)

  if err != nil{
    return 500, "Error creating token"
  }

  return 200, tokenString
}

func findApp(id string) App {
  for _, app := range apps {
    if app.Id == id {
      return app
    }
  }

  return App{}
}

