package main

import (
    "crypto/md5"
    "database/sql"
    "encoding/hex"
    "fmt"
    "log"
    "net"
    "strings"
    "time"

    _ "github.com/ClickHouse/clickhouse-go"
)

// Структура для хранения данных
type LogEntry struct {
    Action    string
    RuleID    string
    AlertText string
    Component string
    Protocol  string
    SrcIP     string
    SrcPort   string
    DstIP     string
    DstPort   string
    Timestamp time.Time
    UniqueID  string // Уникальный идентификатор
}

// Функция для генерации уникального идентификатора (MD5-хэш строки)
func generateUniqueID(entry *LogEntry) string {
    data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s",
        entry.Action,
        entry.RuleID,
        entry.AlertText,
        entry.Component,
        entry.Protocol,
        entry.SrcIP,
        entry.SrcPort,
        entry.DstIP,
        entry.DstPort,
    )
    hash := md5.Sum([]byte(data))
    return hex.EncodeToString(hash[:])
}

// Функция для очистки строки от неподходящих символов
func sanitizeString(input string) string {
    return strings.Map(func(r rune) rune {
        if r >= 32 && r <= 126 { // ASCII-символы
            return r
        }
        return -1 // Удаляет неподходящий символ
    }, input)
}

// Парсинг входного сообщения
func parseMessage(message string) (*LogEntry, error) {
    message = sanitizeString(message)
    parts := strings.Split(message, " ")
    if len(parts) < 8 {
        return nil, fmt.Errorf("invalid message format")
    }

    entry := &LogEntry{
        Action:    strings.Trim(parts[0], "[]"),
        Timestamp: time.Now(),
    }

    for i, part := range parts {
        switch {
        case strings.HasPrefix(part, "[") && strings.HasSuffix(part, "]") && strings.Count(part, ":") == 2:
            entry.RuleID = strings.Trim(part, "[]")
        case strings.Contains(part, "ICMP") || strings.Contains(part, "UDP"):
            entry.Protocol = strings.Trim(part, "{}")
        case strings.Contains(part, "->"):
            ipParts := strings.Split(part, "->")
            if len(ipParts) == 2 {
                src := strings.Split(ipParts[0], ":")
                dst := strings.Split(ipParts[1], ":")
                if len(src) == 2 && len(dst) == 2 {
                    entry.SrcIP, entry.SrcPort = src[0], src[1]
                    entry.DstIP, entry.DstPort = dst[0], dst[1]
                }
            }
        case strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">"):
            entry.Component = strings.Trim(part, "<>")
        default:
            if i > 0 && parts[i-1] != entry.RuleID && entry.AlertText == "" {
                entry.AlertText = strings.Join(parts[1:], " ")
            }
        }
    }

    // Генерация уникального идентификатора
    entry.UniqueID = generateUniqueID(entry)
    return entry, nil
}

// Вставка данных в ClickHouse
func insertIntoClickhouse(db *sql.DB, entry *LogEntry) error {
    // Начинаем транзакцию
    tx, err := db.Begin()
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    defer tx.Rollback() // Если произойдёт ошибка, откатываем транзакцию

    // Подготавливаем запрос для пакетной вставки
    stmt, err := tx.Prepare(`
        INSERT INTO logs (action, rule_id, alert_text, component, protocol, src_ip, src_port, dst_ip, dst_port, timestamp, unique_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
    if err != nil {
        return fmt.Errorf("failed to prepare statement: %w", err)
    }
    defer stmt.Close()

    // Выполняем вставку
    _, err = stmt.Exec(
        entry.Action,
        entry.RuleID,
        entry.AlertText,
        entry.Component,
        entry.Protocol,
        entry.SrcIP,
        entry.SrcPort,
        entry.DstIP,
        entry.DstPort,
        entry.Timestamp,
        entry.UniqueID,
    )
    if err != nil {
        return fmt.Errorf("failed to execute batch insert: %w", err)
    }

    // Подтверждаем транзакцию
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }

    log.Printf("Successfully inserted entry: %+v", entry)
    return nil
}

func main() {
    // Подключение к ClickHouse
    conn, err := sql.Open("clickhouse", "tcp://127.0.0.1:9000?username=default&password=3525")
    if err != nil {
        log.Fatalf("Error connecting to ClickHouse: %v", err)
    }
    defer conn.Close()

    // Создаём таблицу, если её нет
    _, err = conn.Exec(`
        CREATE TABLE IF NOT EXISTS logs (
            action String,
            rule_id String,
            alert_text String,
            component String,
            protocol String,
            src_ip String,
            src_port String,
            dst_ip String,
            dst_port String,
            timestamp DateTime,
            unique_id String
        ) ENGINE = MergeTree()
        ORDER BY (unique_id, timestamp)
        PRIMARY KEY (unique_id)
    `)
    if err != nil {
        log.Fatalf("Error creating table: %v", err)
    }

    // Слушаем порт 515
    addr := net.UDPAddr{
        Port: 515,
        IP:   net.IPv4(0, 0, 0, 0),
    }
    connUDP, err := net.ListenUDP("udp", &addr)
    if err != nil {
        log.Fatalf("Error starting UDP listener: %v", err)
    }
    defer connUDP.Close()

    log.Println("Listening on port 515...")

    buffer := make([]byte, 8192) // Увеличиваем буфер для большего количества пакетов
    for {
        n, remoteAddr, err := connUDP.ReadFromUDP(buffer)
        if err != nil {
            log.Printf("Error reading UDP packet: %v", err)
            continue
        }

        log.Printf("Received packet from %v", remoteAddr)
        message := string(buffer[:n])
        entry, err := parseMessage(message)
        if err != nil {
            log.Printf("Error parsing message: %v, Raw message: %s", err, message)
            continue
        }

        err = insertIntoClickhouse(conn, entry)
        if err != nil {
            log.Printf("Error inserting into database: %v", err)
        }
    }
}
