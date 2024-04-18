package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"go_sql/config"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
)

var serverError = errors.New("server error")

type apiFunc func(http.ResponseWriter, *http.Request) error

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
	listenAddr  string
	store       Storage
	timeOut     time.Duration
	idleTimeOut time.Duration
}

func NewAPIServer(httpServerCfg *config.HttpServer, store Storage) *APIServer {
	return &APIServer{
		listenAddr:  httpServerCfg.Address,
		store:       store,
		timeOut:     httpServerCfg.Timeout,
		idleTimeOut: httpServerCfg.IdleTimeout,
	}
}

func (s *APIServer) Run() {
	err := godotenv.Load("./config/.env")
	if err != nil {
		log.Fatal(err)
	}

	r := chi.NewRouter()
	r.Route("/auth", func(c chi.Router) {
		c.Get("/refresh", s.refresh)
		c.Post("/login", s.handleLogin)
		c.Post("/signup", s.handleCreateAccount)
		c.Get("/logout", s.handleLogout)
	})

	r.Route("/api", func(c chi.Router) {
		c.Get("/account", s.handleGetAccount)
		c.With(s.jwtMiddleware).Get("/account/{id}", s.handleGetAccountById)
		c.With(s.jwtMiddleware).Delete("/account/{id}", s.handleDeleteAccount)
		c.With(s.jwtMiddleware).Put("/account/{id}", s.handleUpdateAccount)
		c.With(s.jwtMiddleware).Post("/account/transfer/{id}", s.handleTransfer)

	})

	log.Println("JSON API server running on port: ", s.listenAddr)

	server := &http.Server{
		Addr:         s.listenAddr,
		IdleTimeout:  s.idleTimeOut,
		ReadTimeout:  s.timeOut,
		WriteTimeout: s.timeOut,
		Handler:      r,
	}
	server.ListenAndServe()
}

func (s *APIServer) refresh(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("refresh-token")
	if err != nil {
		permissionDenied(w)
		return
	}

	refreshToken := cookie.Value
	validatedJWT, err := validateRefreshToken(refreshToken)
	if err != nil {
		permissionDenied(w)
		return
	}
	tokenFromDb, err := s.store.GetRefreshToken(refreshToken)
	if err != nil {
		permissionDenied(w)
		return
	}
	payload := validatedJWT.Claims.(jwt.MapClaims)
	account, err := s.store.GetAccountByID(int(payload["accountId"].(float64)))
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	newJWT, err := createJWT(account)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	newRefreshToken, err := generateRefreshToken(account)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	err = s.store.DeleteRefreshTokenById(tokenFromDb.Id)

	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}

	s.store.CreateRefreshToken(newRefreshToken)

	w.Header().Set("Authorization", "Bearer "+newJWT)
	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		Name:     "refresh-token",
		Value:    newRefreshToken,
	})

	respForDebug := make(map[string]string, 2)
	respForDebug["jwt"] = newJWT
	respForDebug["refresh"] = newRefreshToken

	WriteJSON(w, http.StatusOK, respForDebug)
}

func (s *APIServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL)
	req := new(LoginRequest)
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		permissionDenied(w)
		return
	}
	acc, err := s.store.GetAccountByNumber(int(req.Number))
	if err != nil {
		permissionDenied(w)
		return
	}

	if !acc.ValidatePassword(req.Password) {
		permissionDenied(w)
		return
	}

	token, err := createJWT(acc)
	if err != nil {
		permissionDenied(w)
		return
	}
	refreshToken, err := generateRefreshToken(acc)
	if err != nil {
		permissionDenied(w)
		return
	}

	s.store.CreateRefreshToken(refreshToken)

	w.Header().Set("Set-Cookie", fmt.Sprintf("refresh-token=%s; HttpOnly", refreshToken))
	w.Header().Set("Authorization", "Bearer "+token)

	resp := LoginResponse{
		Token:        token,
		RefreshToken: refreshToken,
		Number:       acc.Number,
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (s *APIServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL)
	cookie, err := r.Cookie("refresh-token")
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("invalid token"))
		return
	}
	if err = s.store.DeleteRefreshToken(cookie.Value); err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	w.Header().Del("Authorization")
	http.SetCookie(w, &http.Cookie{
		HttpOnly: true,
		Name:     "refresh-token",
		Value:    "",
	})
	WriteJSON(w, http.StatusOK, map[string]string{
		"response": "logged out",
	})
}

// GET /account
func (s *APIServer) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	accounts, err := s.store.GetAccounts()
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	WriteJSON(w, http.StatusOK, accounts)

}

// GET /account/{id}
func (s *APIServer) handleGetAccountById(w http.ResponseWriter, r *http.Request) {
	id, err := getId(r)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err)
		return
	}
	account, err := s.store.GetAccountByID(id)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	req := new(CreateAccountRequest)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("bad request"))
		return
	}

	account, err := NewAccount(req.FirstName, req.LastName, req.Password)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	if err := s.store.CreateAccount(account); err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	WriteJSON(w, http.StatusOK, account)
}

func (s *APIServer) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	id, err := getId(r)
	if err != nil {
		permissionDenied(w)
		return
	}
	if err = s.store.DeleteAccount(id); err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]int{"deleted": id})
}

func (s *APIServer) handleTransfer(w http.ResponseWriter, r *http.Request) {
	transferReq := new(TransferRequest)
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(transferReq); err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("invalid data"))
		return
	}
	toAccount, err := s.store.GetAccountByNumber(transferReq.ToAccount)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("no account with this number"))
		return
	}
	fromAccountId, err := getId(r)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("invalid id"))
		return
	}
	fromAccount, err := s.store.GetAccountByID(fromAccountId)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("no account with this number"))
		return
	}
	if fromAccount.Balance-transferReq.Amount < 0 {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("insufficient funds"))
		return
	}
	if err = s.store.Transfer(context.Background(), fromAccount, toAccount, transferReq.Amount); err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]string{
		"response": "success",
	})
}

func createJWT(account *Account) (string, error) {
	claims := &UserClaims{
		AccountNumber: account.Number,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute * 5)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func (s *APIServer) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Calling JWT auth Middleware")
		tokenString, err := getJWT(r)
		if err != nil {
			permissionDenied(w)
			return
		}
		token, err := validateJWT(tokenString)
		if err != nil {
			permissionDenied(w)
			return
		}
		userID, err := getId(r)
		if err != nil {
			permissionDenied(w)
			return
		}
		account, err := s.store.GetAccountByID(userID)
		if err != nil {
			permissionDenied(w)
			return
		}
		claims := token.Claims.(jwt.MapClaims)
		if float64(account.Number) != claims["accountNumber"] {
			permissionDenied(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *APIServer) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	id, err := getId(r)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("invalid id"))
		return
	}
	fmt.Println(id)
	defer r.Body.Close()
	updateReq := new(UpdateAccountRequest)
	if err = json.NewDecoder(r.Body).Decode(updateReq); err != nil {
		WriteJSON(w, http.StatusBadRequest, NewAPIError("invalid data"))
		return
	}
	acc, err := s.store.GetAccountByID(id)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	if updateReq.FirstName == "" {
		updateReq.FirstName = acc.FirstName
	}
	if updateReq.LastName == "" {
		updateReq.LastName = acc.LastName
	}
	if err = s.store.UpdateAccount(updateReq, id); err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{
		"response": "updated",
	})

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

func validateJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
	if err != nil || !token.Valid {

		return nil, err
	}
	return token, nil

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
	idStr := chi.URLParam(r, "id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		return id, fmt.Errorf("invalid id %s", idStr)
	}
	return id, nil
}

func generateRefreshToken(account *Account) (string, error) {
	claims := &RefreshTokenClaims{
		AccountId: account.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24 * 90)),
		},
	}
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return refreshToken.SignedString([]byte(os.Getenv("JWT_SECRET")))
}

func validateRefreshToken(refToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(refToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("JWT_SECRET")), nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return token, nil
}
