package main

import (
	"archive/tar"
	"compress/gzip"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"crypto/tls"

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
	URL  string `mapstructure:"url"`
}

type Signature struct {
	Type     string
	Proto    string
	SrcIP    string
	SrcPort  string
	DstIP    string
	DstPort  string
	SID      string
	Msg      string
	Filename string
}

var config Config

func main() {
	initLog()

	log.Println("=== Старт выполнения парсера для HTTP ===")
	if err := loadConfig(); err != nil {
		log.Fatalf("Ошибка загрузки конфигурации: %v", err)
	}

	db, err := connectToDB(config.DB)
	if err != nil {
		log.Fatalf("Ошибка подключения к БД: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("Ошибка инициализации БД: %v", err)
	}

	for _, source := range config.Sources {
		if source.Type == "suricata" && source.URL != "" {
			log.Printf("Обработка источника: %s", source.Name)
			localFile := fmt.Sprintf("%s_archive.tar.gz", source.Name)
			if err := downloadFileFromHTTP(source.URL, localFile); err != nil {
				log.Printf("Ошибка загрузки файла по URL для источника %s: %v", source.Name, err)
				continue
			}

			if err := processArchive(db, localFile, source.Name); err != nil {
				log.Printf("Ошибка обработки архива для источника %s: %v", source.Name, err)
			}
		}
	}

	log.Println("=== Завершение выполнения парсера для HTTP ===")
}

func initLog() {
	file, err := os.Create("parser.log")
	if err != nil {
		fmt.Printf("Ошибка создания лог-файла: %v\n", err)
		os.Exit(1)
	}
	log.SetOutput(file)
	log.Println("=== Начало выполнения парсера для HTTP ===")
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

func initDB(db *sql.DB) error {
	query := `
CREATE TABLE IF NOT EXISTS signatures (
    id SERIAL PRIMARY KEY,
    type TEXT,
    proto TEXT,
    src_ip TEXT,
    src_port TEXT,
    dst_ip TEXT,
    dst_port TEXT,
    sid TEXT UNIQUE,
    msg TEXT,
    filename TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT NULL,
    deleted_at TIMESTAMP DEFAULT NULL
);
`
	_, err := db.Exec(query)
	return err
}

func downloadFileFromHTTP(url, localFile string) error {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("Ошибка загрузки файла по URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP ошибка: %s", resp.Status)
	}

	out, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("Ошибка создания локального файла: %v", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("Ошибка сохранения файла: %v", err)
	}

	log.Printf("Файл успешно загружен по URL: %s", localFile)
	return nil
}

func processArchive(db *sql.DB, archive string, sourceName string) error {
	file, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("Ошибка открытия архива: %v", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("Ошибка открытия GZIP: %v", err)
	}
	defer gzr.Close()

	tarReader := tar.NewReader(gzr)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Ошибка чтения TAR: %v", err)
			continue
		}

		if header.Typeflag == tar.TypeReg {
			log.Printf("Обработка файла: %s", header.Name)
			if err := parseFile(db, tarReader, header.Name, sourceName); err != nil {
				log.Printf("Ошибка обработки файла %s: %v", header.Name, err)
			}
		}
	}
	return nil
}

func parseFile(db *sql.DB, reader io.Reader, filename string, sourceName string) error {
	re := regexp.MustCompile(`(?is)alert (\w+) (\[.*?\]|\S+) any -> (\[.*?\]|\S+) any .*?msg:"(.*?)";.*?sid:(\d+);`)
	buf := new(strings.Builder)

	_, err := io.Copy(buf, reader)
	if err != nil {
		return fmt.Errorf("Ошибка чтения содержимого файла: %v", err)
	}

	content := buf.String()
	content = strings.ReplaceAll(content, "\n", " ") // Убираем переносы строк

	matches := re.FindAllStringSubmatch(content, -1)
	log.Printf("Найдено совпадений: %d", len(matches))
	if len(matches) == 0 {
		log.Printf("Файл %s не содержит подходящих сигнатур", filename)
		return nil
	}

	for _, match := range matches {
		if len(match) < 6 {
			log.Printf("Некорректное совпадение: %v", match)
			continue
		}

		// Убираем дублирующийся массив IP из сообщения
		msg := match[4]
		if strings.Contains(msg, "ip [") {
			start := strings.Index(msg, "ip [")
			end := strings.Index(msg[start:], "]") + start + 1
			msg = msg[:start] + msg[end:]
		}

		// Создаём структуру сигнатуры.
		sig := Signature{
			Type:     match[1],
			Proto:    match[2],
			SrcIP:    match[3],
			SrcPort:  "", // Пока не заполняем, так как это будет заполнено при импорте FTP
			DstIP:    match[4],
			DstPort:  "", // Пока не заполняем, так как это будет заполнено при импорте FTP
			Msg:      msg,
			SID:      match[5],
			Filename: filename,
		}

		// Сохраняем в базу данных
		if err := saveToDB(db, sig); err != nil {
			log.Printf("Ошибка сохранения записи (SID: %s): %v", sig.SID, err)
			continue
		}
	}
	return nil
}

func saveToDB(db *sql.DB, sig Signature) error {
	query := `
INSERT INTO signatures (type, proto, src_ip, src_port, dst_ip, dst_port, sid, msg, filename, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
ON CONFLICT (sid) DO UPDATE SET 
    type = EXCLUDED.type,
    proto = EXCLUDED.proto,
    src_ip = EXCLUDED.src_ip,
    src_port = EXCLUDED.src_port,
    dst_ip = EXCLUDED.dst_ip,
    dst_port = EXCLUDED.dst_port,
    msg = EXCLUDED.msg,
    filename = EXCLUDED.filename,
    updated_at = CURRENT_TIMESTAMP
WHERE signatures.sid = EXCLUDED.sid AND (
    signatures.type != EXCLUDED.type OR
    signatures.proto != EXCLUDED.proto OR
    signatures.src_ip != EXCLUDED.src_ip OR
    signatures.src_port != EXCLUDED.src_port OR
    signatures.dst_ip != EXCLUDED.dst_ip OR
    signatures.dst_port != EXCLUDED.dst_port OR
    signatures.msg != EXCLUDED.msg OR
    signatures.filename != EXCLUDED.filename
);
`
	_, err := db.Exec(query, sig.Type, sig.Proto, sig.SrcIP, sig.SrcPort, sig.DstIP, sig.DstPort, sig.SID, sig.Msg, sig.Filename)
	return err
}