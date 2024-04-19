package main

import (
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
)

//var validate *validator.Validate

type LoginResponse struct {
	Number       int64  `json:"number"`
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

type UserClaims struct {
	AccountNumber int64 `json:"accountNumber"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	AccountId int `json:"accountId"`
	jwt.RegisteredClaims
}

type EmailVerify struct {
	Id         int    `json:"id"`
	AccountNum int    `json:"accountNum"`
	UuidUrl    string `json:"uuid_Url"`
}

type RefreshToken struct {
	Id    int    `json:"id"`
	Token string `json:"token"`
}

type LoginRequest struct {
	Number   int64  `json:"number"`
	Password string `json:"password" `
}

type TransferRequest struct {
	ToAccount int   `json:"toAccount"`
	Amount    int64 `json:"amount"`
}

type CreateAccountRequest struct {
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type UpdateAccountRequest struct {
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

type Account struct {
	ID                int       `json:"id"`
	FirstName         string    `json:"firstName"`
	LastName          string    `json:"lastName"`
	EncryptedPassword string    `json:"-"`
	Email             string    `json:"email"`
	IsVerified        bool      `json:"isVerified"`
	Number            int64     `json:"number"`
	Balance           int64     `json:"balance"`
	CreatedAt         time.Time `json:"createdAt"`
}

func (a *Account) ValidatePassword(pw string) bool {
	return bcrypt.CompareHashAndPassword([]byte(a.EncryptedPassword), []byte(pw)) == nil
}

func NewAccount(req *CreateAccountRequest) (*Account, error) {
	encPw, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return &Account{
		FirstName:         req.FirstName,
		LastName:          req.LastName,
		EncryptedPassword: string(encPw),
		Email:             req.Email,
		Number:            int64(rand.Intn(10000000)),
		CreatedAt:         time.Now().UTC(),
	}, nil
}

func NewEmailVerification(accountNum int) (*EmailVerify, error) {
	uuid_url, err := uuid.NewUUID()
	if err != nil {
		return nil, err
	}
	return &EmailVerify{
		AccountNum: accountNum,
		UuidUrl:    uuid_url.String(),
	}, nil
}
