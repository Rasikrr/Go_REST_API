package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
)

type Storage interface {
	CreateAccount(*Account) error
	GetAccountByID(int) (*Account, error)
	GetAccounts() ([]*Account, error)
	DeleteAccount(int) error
	UpdateAccount(*Account) error
	GetAccountByNumber(int) (*Account, error)
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore() (*PostgresStore, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s password=%s",
		"127.0.0.1", "5432", "Rasik", "postgres", "disable", "rasik1234")
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) Init() error {
	return s.createAccountTable()
}

func (s *PostgresStore) createAccountTable() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS account(
    	id SERIAL PRIMARY KEY,
    	first_name VARCHAR(50) NOT NULL,
    	last_name VARCHAR(50) NOT NULL,
    	encrypted_password VARCHAR(100) NOT NULL,
    	number SERIAL,
    	balance BIGINT,
    	created_at TIMESTAMP
	)`)
	return err
}

func (s *PostgresStore) CreateAccount(account *Account) error {
	query := `INSERT INTO account
    (first_name, last_name, encrypted_password, number, balance, created_at)
	VALUES($1, $2, $3, $4, $5, $6)`
	_, err := s.db.Exec(
		query,
		account.FirstName,
		account.LastName,
		account.EncryptedPassword,
		account.Number,
		account.Balance,
		account.CreatedAt,
	)
	return err
}

func (s *PostgresStore) GetAccountByID(id int) (*Account, error) {
	account := new(Account)
	row := s.db.QueryRow(`SELECT * FROM account WHERE id=$1`, id)
	err := row.Scan(&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Number,
		&account.Balance,
		&account.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("account %d not found", id)
	}
	return account, nil
}

func (s *PostgresStore) GetAccountByNumber(num int) (*Account, error) {
	query := `SELECT * FROM account WHERE number=$1`
	account := new(Account)
	row := s.db.QueryRow(query, num)
	err := row.Scan(&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Number,
		&account.Balance,
		&account.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("account with number %d not found", num)
	}
	return account, nil
}

func (s *PostgresStore) GetAccounts() ([]*Account, error) {
	query := `SELECT * FROM account`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	accounts := make([]*Account, 0)
	for rows.Next() {
		account, err := scanIntoAccounts(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, account)
	}
	return accounts, nil
}

func (s *PostgresStore) DeleteAccount(id int) error {
	query := `DELETE FROM account WHERE id=$1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStore) UpdateAccount(account *Account) error {
	return nil
}

func scanIntoAccounts(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.Number,
		&account.Balance,
		&account.CreatedAt,
	)
	return account, err

}
