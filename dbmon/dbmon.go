package dbmon

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"go.uber.org/zap"
	"github.com/xFaraday/gomemento/common"
	"os/exec"
)

var (
	username string
	password string
	host     string
)

var (
	mysqldumppath = "/opt/memento/backups/backupMySQL.sql"
	psqldumppath  = "/opt/memento/backups/backupPSQL.out"
)

func DetectDatabase(username string, password string, host string) string {
	PsqlconnStr := "user=" + username + " password=" + password + " host=" + host + " dbname=postgres sslmode=disable"
	MysqlconnStr := username + ":" + password + "@tcp(" + host + ":3306)/mysql"

	db, err := sql.Open("mysql", MysqlconnStr)
	if err != nil {
		zap.S().Info("Database MySQL: UNABLE TO CONNECT")
	}
	if err := db.Ping(); err == nil {
		return "mysql"
	}
	defer db.Close()

	db, err = sql.Open("postgres", PsqlconnStr)
	if err != nil {
		zap.S().Info("Database PostSQL: UNABLE TO CONNECT")
	}
	if err := db.Ping(); err == nil {
		return "postgres"
	}
	defer db.Close()
	return "unknown"
}

func GetMySQLDatabases() []string {
	var results []string
	db, err := sql.Open("mysql", username+":"+password+"@tcp("+host+":3306)/mysql")
	if err != nil {
		zap.S().Info("Database MySQL: UNABLE TO CONNECT")
	}
	defer db.Close()
	rows, err := db.Query("SHOW DATABASES")
	if err != nil {
		zap.S().Info("Database MySQL: UNABLE TO GET DATABASES")
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			zap.S().Info("Database MySQL: UNABLE TO GET DATABASES")
		}
		results = append(results, name)
	}
	return results
}

func RestoreMySQL() {

}

func RestorePostgres() {

}

func DetectChanges() {
	//dump database again and compare hashes of previous backup to temporary backup
	//if hashes are different, alert, then restore
}

func BackupMysql() {
	mysqldumpbin := common.FindTrueBinary("mysqldump")
	fullstr := mysqldumpbin + " -u" + username + " -p" + password + " --all-databases > " + mysqldumppath
	serviceListOut, err := exec.Command("bash", "-c", fullstr).Output()
	if err != nil {
		zap.S().Info("Database MySQL: UNABLE TO BACKUP")
	}
	zap.S().Info("Database MySQL: BACKUP SUCCESSFUL")
	zap.S().Info(string(serviceListOut))
}

func BackupPostgres() {
	psqldumpbin := common.FindTrueBinary("pg_dumpall")
	fullstr := psqldumpbin + " -U " + username + " -h " + host + " > " + psqldumppath
	serviceListOut, err := exec.Command("bash", "-c", fullstr).Output()
	if err != nil {
		zap.S().Info("Database Postgres: UNABLE TO BACKUP")
	}
	zap.S().Info("Database Postgres: BACKUP SUCCESSFUL")
	zap.S().Info(string(serviceListOut))
}

func BackupController() {
	switch DetectDatabase(username, password, host) {
	case "mysql":
		BackupMysql()
	case "postgres":
		BackupPostgres()
	default:
		zap.S().Info("Database: UNABLE TO DETECT, are you sure its there?")
	}
}