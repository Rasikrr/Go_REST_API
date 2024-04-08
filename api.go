package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

type apiFunc func(http.ResponseWriter, *http.Request) error

const JWT_SECRET = "rasik1234"

type APIError struct {
	Error string `json:"error"`
}

var invalidTokenError = errors.New("invalid token")

func NewAPIError(s string) *APIError {
	return &APIError{Error: s}
}

func permissionDenied(w http.ResponseWriter) {
	WriteJSON(w, http.StatusForbidden, NewAPIError("permission denied"))
}

type APIServer struct {
	listenAddr string
	store      Storage
}

func NewAPIServer(listenAddr string, store Storage) *APIServer {
	return &APIServer{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *APIServer) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/account", makeHTTPHandleFunc(s.handleAccount))
	router.HandleFunc("/account/{id}", withJWTAuth(makeHTTPHandleFunc(s.handleSingleAccount), s.store))

	router.HandleFunc("/transfer", makeHTTPHandleFunc(s.handleTransfer))

	router.HandleFunc("/login", makeHTTPHandleFunc(s.handleLogin))

	log.Println("JSON API server running on port: ", s.listenAddr)

	http.ListenAndServe(s.listenAddr, router)

}

func (s *APIServer) handleAccount(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		return s.handleGetAccount(w, r)
	case "POST":
		return s.handleCreateAccount(w, r)
	}
	return fmt.Errorf("method not allowed: %s", r.Method)
}

// 1552347
func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) error {
	if r.Method != "POST" {
		return fmt.Errorf("method not allowed %s", r.Method)
	}
	req := new(LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}
	fmt.Println(req.Number)
	acc, err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		return err
	}

	if !acc.ValidatePassword(req.Password) {
		return fmt.Errorf("not authenticated")
	}

	token, err := createJWT(acc)
	if err != nil {
		return err
	}
	fmt.Println(token)

	w.Header().Set("Authorization", "Bearer "+token)

	resp := LoginResponse{
		Token:  token,
		Number: acc.Number,
	}

	fmt.Printf("%+v\n", acc)

	return WriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleSingleAccount(w http.ResponseWriter, r *http.Request) error {
	switch r.Method {
	case "GET":
		return s.handleGetAccountById(w, r)
	case "DELETE":
		return s.handleDeleteAccount(w, r)
	}
	return fmt.Errorf("method is not allowed: %s", r.Method)
}

// GET /account
func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) error {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, accounts)

}

// GET /account/{id}
func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request) error {
	id, err := getId(r)
	if err != nil {
		return err
	}
	account, err := s.store.GetAccountByID(id)
	if err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) error {
	req := new(CreateAccountRequest)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		return err
	}

	account, err := NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		return err
	}
	if err := s.store.CreateAccount(account); err != nil {
		return err
	}

	return WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) error {
	id, err := getId(r)
	if err != nil {
		return err
	}
	if err = s.store.DeleteAccount(id); err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) error {
	transferReq := new(TransferRequest)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		return err
	}
	return WriteJSON(w, http.StatusOK, transferReq)
}

func createJWT(account *Account) (string, error) {
	claims := &UserClaims{
		AccountNumber: account.Number,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Second * 300)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString([]byte(JWT_SECRET))
}

func withJWTAuth(handleFunc http.HandlerFunc, s Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Calling JWT auth Middleware")

		tokenString, err := getJWT(r)
		if err != nil {
			permissionDenied(w)
		}
		fmt.Println(tokenString)
		token, err := validateJWT(tokenString)
		fmt.Println(token)

		if err != nil || !token.Valid {
			fmt.Println(token.Valid)
			permissionDenied(w)
			return
		}
		userID, err := getId(r)
		if err != nil {
			permissionDenied(w)
			return
		}
		fmt.Println("No error")
		account, err := s.GetAccountByID(userID)
		if err != nil {
			fmt.Println(err)
			permissionDenied(w)
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		fmt.Println("%t %d %t %d\n", claims["accountNumber"], claims["accountNumber"], account.Number, account.Number)
		if float64(account.Number) != claims["accountNumber"] {
			permissionDenied(w)
			return
		}
		handleFunc(w, r)
	}
}

func getJWT(r *http.Request) (string, error) {
	headerValue := r.Header.Get("Authorization")
	if headerValue == "" {
		return "", invalidTokenError
	}
	token := strings.Split(headerValue, " ")
	if len(token) != 2 {
		return "", invalidTokenError
	}
	return token[1], nil

}

// 603571
func validateJWT(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(JWT_SECRET), nil
		})

}

func WriteJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func makeHTTPHandleFunc(f apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteJSON(w, http.StatusBadRequest, APIError{err.Error()})
		}
	}
}

func getId(r *http.Request) (int, error) {
	idStr := mux.Vars(r)["id"]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id %s", idStr)
	}
	return id, nil
}
