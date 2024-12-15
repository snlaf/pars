package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/spf13/viper"
)

type Config struct {
	DB      DBConfig        `mapstructure:"db"`
	Sources []SourceConfig  `mapstructure:"sources"`
}

type DBConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"`
}

type SourceConfig struct {
	Name string `mapstructure:"name"`
	Type string `mapstructure:"type"`
	FTP  string `mapstructure:"ftp"`
	Path string `mapstructure:"path"`
}

type Signature struct {
	Type     string
	Proto    string
	SrcIP    string
	DstIP    string
	SID      string
	Msg      string
	Filename string
}

type ExportFormat string

const (
	Suricata ExportFormat = "suricata"
	Dionis   ExportFormat = "dionis"
)

var config Config

func main() {
	initLog()

	log.Println("=== Старт выполнения экспорта ===")
	if err := loadConfig(); err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	db, err := connectToDB(config.DB)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}
	defer db.Close()

	if err := exportSignatures(db, Suricata, "export_suricata.txt"); err != nil {
		log.Printf("Ошибка экспорта в Suricata: %v", err)
	} else {
		log.Println("Экспорт для Suricata завершён успешно.")
	}

	if err := exportSignatures(db, Dionis, "export_dionis.txt"); err != nil {
		log.Printf("Ошибка экспорта в Dionis: %v", err)
	} else {
		log.Println("Экспорт для Dionis завершён успешно.")
	}

	log.Println("=== Завершение выполнения экспорта ===")
}

func initLog() {
	file, err := os.Create("parser.log")
	if err != nil {
		fmt.Printf("Ошибка создания лог-файла: %v\n", err)
		os.Exit(1)
	}
	log.SetOutput(file)
	log.Println("=== Начало выполнения экспорта ===")
}

func loadConfig() error {
	viper.SetConfigName("locals")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("Ошибка чтения файла конфигурации: %v", err)
	}
	return viper.Unmarshal(&config)
}

func connectToDB(dbConfig DBConfig) (*sql.DB, error) {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		dbConfig.Host, dbConfig.Port, dbConfig.User, dbConfig.Password, dbConfig.Name)
	return sql.Open("postgres", connStr)
}

func exportSignatures(db *sql.DB, format ExportFormat, outputFile string) error {
	rows, err := db.Query(`
        SELECT type, proto, src_ip, dst_ip, sid, msg, filename 
        FROM signatures
        WHERE deleted_at IS NULL
    `)
	if err != nil {
		return fmt.Errorf("Ошибка выполнения запроса: %v", err)
	}
	defer rows.Close()

	var outputData []string

	for rows.Next() {
		var sig Signature
		var msg sql.NullString
		var filename sql.NullString

		if err := rows.Scan(&sig.Type, &sig.Proto, &sig.SrcIP, &sig.DstIP, &sig.SID, &msg, &filename); err != nil {
			return fmt.Errorf("Ошибка сканирования данных: %v", err)
		}

		// Обработка nullable полей
		if msg.Valid {
			sig.Msg = msg.String
		} else {
			sig.Msg = "N/A" // Значение по умолчанию для NULL
		}

		if filename.Valid {
			sig.Filename = filename.String
		} else {
			sig.Filename = "N/A" // Значение по умолчанию для NULL
		}

		switch format {
		case Suricata:
			outputData = append(outputData, fmt.Sprintf(
				"\nalert %s %s %s -> %s any (msg:\"%s\"; sid:%s;);",
				sig.Type, sig.Proto, sig.SrcIP, sig.DstIP, sig.Msg, sig.SID,
			))
		case Dionis:
			outputData = append(outputData, fmt.Sprintf(
				"\ntype:%s;proto:%s;src_ip:%s;dst_ip:%s;sid:%s;msg:%s;filename:%s;",
				sig.Type, sig.Proto, sig.SrcIP, sig.DstIP, sig.SID, sig.Msg, sig.Filename,
			))
		default:
			return fmt.Errorf("Неподдерживаемый формат экспорта: %v", format)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("Ошибка при чтении строк: %v", err)
	}

	// Запись результата в файл.
	err = os.WriteFile(outputFile, []byte(strings.Join(outputData, "")), 0644) // Убираем лишние разделители между строками
	if err != nil {
		return fmt.Errorf("Ошибка записи в файл %s: %v", outputFile, err)
	}

	log.Printf("Экспорт завершён. Данные сохранены в файл: %s", outputFile)
	return nil
}