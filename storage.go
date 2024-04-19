package main

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"go_sql/config"
)

type Storage interface {
	CreateAccount(*Account) error
	GetAccountByID(int) (*Account, error)
	GetAccounts() ([]*Account, error)
	DeleteAccount(int) error
	UpdateAccount(request *UpdateAccountRequest, id int) error
	GetAccountByNumber(int) (*Account, error)
	VerifyAccountById(int) error

	Transfer(context.Context, *Account, *Account, int64) error

	CreateRefreshToken(string) error
	DeleteRefreshToken(string) error
	DeleteRefreshTokenById(int) error
	GetRefreshToken(string) (*RefreshToken, error)

	CreateEmailVerification(*EmailVerify) error
	GetEmailVerificationByUUID(string) (*EmailVerify, error)
	DeleteEmailVerificationById(int) error
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(dbCfg *config.Storage) (*PostgresStore, error) {
	connStr := fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=%s password=%s",
		dbCfg.Host, dbCfg.Port, dbCfg.User, dbCfg.Dbname, dbCfg.SslMode, dbCfg.Password)
	db, err := sql.Open(dbCfg.DriverName, connStr)
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
	err := s.createAccountTable()
	if err != nil {
		return err
	}
	err = s.createEmailVerifyTable()
	if err != nil {
		return err
	}
	return s.createRefreshTokensTable()

}

func (s *PostgresStore) createAccountTable() error {
	_, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS account(
    	id SERIAL PRIMARY KEY,
    	first_name VARCHAR(50) NOT NULL,
    	last_name VARCHAR(50) NOT NULL,
    	encrypted_password VARCHAR(100) NOT NULL,
    	email VARCHAR(50) NOT NULL UNIQUE,
    	is_verified BOOLEAN DEFAULT FALSE,
    	number INT NOT NULL UNIQUE,
    	balance BIGINT,
    	created_at TIMESTAMP
	);`)
	return err
}

func (s *PostgresStore) createRefreshTokensTable() error {
	query := `CREATE TABLE IF NOT EXISTS refresh_tokens(
	id SERIAL PRIMARY KEY,
	token VARCHAR(255) NOT NULL UNIQUE
	);`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) createEmailVerifyTable() error {
	query := `CREATE TABLE IF NOT EXISTS email_verify(
	id SERIAL PRIMARY KEY,
	account_num INT,
	uuid_url VARCHAR(50),
	FOREIGN KEY (account_num) REFERENCES account(number) ON DELETE CASCADE
	);`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) GetEmailVerificationByUUID(uuid string) (*EmailVerify, error) {
	verif := new(EmailVerify)
	query := `SELECT * FROM email_verify WHERE uuid_url=$1`
	row := s.db.QueryRow(query, uuid)
	err := row.Scan(&verif.Id,
		&verif.AccountNum,
		&verif.UuidUrl,
	)
	if err != nil {
		return nil, err
	}
	return verif, nil
}

func (s *PostgresStore) DeleteEmailVerificationById(id int) error {
	query := `DELETE FROM email_verify WHERE id=$1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStore) CreateEmailVerification(req *EmailVerify) error {
	query := `INSERT INTO email_verify(account_num, uuid_url)
	VALUES($1, $2)`
	_, err := s.db.Exec(query, req.AccountNum, req.UuidUrl)
	return err
}

func (s *PostgresStore) CreateRefreshToken(refToken string) error {
	query := `INSERT INTO refresh_tokens(token)
		VALUES ($1)`
	_, err := s.db.Exec(query, refToken)
	return err
}

func (s *PostgresStore) GetRefreshToken(token string) (*RefreshToken, error) {
	query := `SELECT id, token FROM refresh_tokens WHERE token=$1`
	refToken := new(RefreshToken)
	row := s.db.QueryRow(query, token)
	err := row.Scan(&refToken.Id, &refToken.Token)
	return refToken, err
}

func (s *PostgresStore) DeleteRefreshTokenById(id int) error {
	query := `DELETE FROM refresh_tokens WHERE id=$1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStore) DeleteRefreshToken(tkn string) error {
	query := `DELETE FROM refresh_tokens WHERE token=$1`
	_, err := s.db.Exec(query, tkn)
	return err
}

func (s *PostgresStore) CreateAccount(account *Account) error {
	query := `INSERT INTO account
    (first_name, last_name, encrypted_password, email, number, balance, created_at)
	VALUES($1, $2, $3, $4, $5, $6, $7)`
	_, err := s.db.Exec(
		query,
		account.FirstName,
		account.LastName,
		account.EncryptedPassword,
		account.Email,
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
		&account.EncryptedPassword,
		&account.Email,
		&account.IsVerified,
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
		&account.EncryptedPassword,
		&account.Email,
		&account.IsVerified,
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

func (s *PostgresStore) UpdateAccount(updateReq *UpdateAccountRequest, id int) error {
	query := `UPDATE account SET first_name=$1, last_name=$2 WHERE id=$3`
	_, err := s.db.Exec(query, updateReq.FirstName, updateReq.LastName, id)
	return err
}

func (s *PostgresStore) VerifyAccountById(id int) error {
	query := `UPDATE account SET is_verified=true WHERE id=$1`
	_, err := s.db.Exec(query, id)
	return err
}

func (s *PostgresStore) Transfer(ctx context.Context, from *Account, to *Account, amount int64) error {
	query1 := `UPDATE account 
			SET balance=balance-$1
			WHERE id=$2`
	query2 := `UPDATE account
			SET balance=balance+$1
			WHERE id=$2`
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		fmt.Println(1, err)
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(query1, amount, from.ID); err != nil {
		fmt.Println(2, err)
		return err
	}
	if _, err = tx.Exec(query2, amount, to.ID); err != nil {
		fmt.Println(3, err)
		return err
	}
	return tx.Commit()

}

func scanIntoAccounts(rows *sql.Rows) (*Account, error) {
	account := new(Account)
	err := rows.Scan(
		&account.ID,
		&account.FirstName,
		&account.LastName,
		&account.EncryptedPassword,
		&account.Email,
		&account.IsVerified,
		&account.Number,
		&account.Balance,
		&account.CreatedAt,
	)
	return account, err

}
