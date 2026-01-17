package main

import (
    "encoding/json"
    "log"
    "net/http"
    "strings"
    "time"
    "github.com/dgrijalva/jwt-go"
    "golang.org/x/crypto/bcrypt"
)

// Структуры данных
type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password,omitempty"`
}

type LoginRequest struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type RegisterRequest struct {
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
}

type AuthResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message"`
    Token   string `json:"token,omitempty"`
    User    *User  `json:"user,omitempty"`
}

// Конфигурация
var (
    jwtSecret     = []byte("your-secret-key-change-in-production")
    users         = make(map[string]User)
    userCounter   = 1
)

// Функция для хеширования пароля
func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
    return string(bytes), err
}

// Функция для проверки пароля
func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// Создание JWT токена
func createToken(username string) (string, error) {
    token := jwt.New(jwt.SigningMethodHS256)
    
    claims := token.Claims.(jwt.MapClaims)
    claims["username"] = username
    claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Токен на 24 часа
    
    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        return "", err
    }
    
    return tokenString, nil
}

// Проверка JWT токена
func verifyToken(tokenString string) (bool, string) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        return jwtSecret, nil
    })
    
    if err != nil {
        return false, ""
    }
    
    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        username := claims["username"].(string)
        return true, username
    }
    
    return false, ""
}

// Middleware для проверки авторизации
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Missing authorization header", http.StatusUnauthorized)
            return
        }
        
        tokenParts := strings.Split(authHeader, " ")
        if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
            http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
            return
        }
        
        valid, username := verifyToken(tokenParts[1])
        if !valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }
        
        // Добавляем username в контекст запроса
        r.Header.Set("X-Username", username)
        next(w, r)
    }
}

// Обработчик регистрации
func registerHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var req RegisterRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Проверка входных данных
    if req.Username == "" || req.Email == "" || req.Password == "" {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "All fields are required",
        }, http.StatusBadRequest)
        return
    }
    
    // Проверка существования пользователя
    if _, exists := users[req.Username]; exists {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Username already exists",
        }, http.StatusConflict)
        return
    }
    
    // Хеширование пароля
    hashedPassword, err := hashPassword(req.Password)
    if err != nil {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Error processing password",
        }, http.StatusInternalServerError)
        return
    }
    
    // Создание пользователя
    user := User{
        ID:       userCounter,
        Username: req.Username,
        Email:    req.Email,
        Password: hashedPassword,
    }
    
    users[req.Username] = user
    userCounter++
    
    // Создание токена
    token, err := createToken(req.Username)
    if err != nil {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Error creating token",
        }, http.StatusInternalServerError)
        return
    }
    
    // Убираем пароль из ответа
    user.Password = ""
    
    sendJSONResponse(w, AuthResponse{
        Success: true,
        Message: "Registration successful",
        Token:   token,
        User:    &user,
    }, http.StatusCreated)
}

// Обработчик входа
func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var req LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid request body", http.StatusBadRequest)
        return
    }
    
    // Проверка входных данных
    if req.Username == "" || req.Password == "" {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Username and password are required",
        }, http.StatusBadRequest)
        return
    }
    
    // Поиск пользователя
    user, exists := users[req.Username]
    if !exists {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Invalid credentials",
        }, http.StatusUnauthorized)
        return
    }
    
    // Проверка пароля
    if !checkPasswordHash(req.Password, user.Password) {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Invalid credentials",
        }, http.StatusUnauthorized)
        return
    }
    
    // Создание токена
    token, err := createToken(req.Username)
    if err != nil {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Error creating token",
        }, http.StatusInternalServerError)
        return
    }
    
    // Убираем пароль из ответа
    user.Password = ""
    
    sendJSONResponse(w, AuthResponse{
        Success: true,
        Message: "Login successful",
        Token:   token,
        User:    &user,
    }, http.StatusOK)
}

// Обработчик проверки токена
func verifyHandler(w http.ResponseWriter, r *http.Request) {
    token := r.URL.Query().Get("token")
    if token == "" {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Token is required",
        }, http.StatusBadRequest)
        return
    }
    
    valid, username := verifyToken(token)
    if !valid {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "Invalid token",
        }, http.StatusUnauthorized)
        return
    }
    
    user, exists := users[username]
    if !exists {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "User not found",
        }, http.StatusNotFound)
        return
    }
    
    user.Password = ""
    
    sendJSONResponse(w, AuthResponse{
        Success: true,
        Message: "Token is valid",
        User:    &user,
    }, http.StatusOK)
}

// Обработчик получения профиля (защищенный)
func profileHandler(w http.ResponseWriter, r *http.Request) {
    username := r.Header.Get("X-Username")
    
    user, exists := users[username]
    if !exists {
        sendJSONResponse(w, AuthResponse{
            Success: false,
            Message: "User not found",
        }, http.StatusNotFound)
        return
    }
    
    user.Password = ""
    
    sendJSONResponse(w, AuthResponse{
        Success: true,
        Message: "Profile retrieved successfully",
        User:    &user,
    }, http.StatusOK)
}

// Вспомогательная функция для отправки JSON ответов
func sendJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    w.WriteHeader(statusCode)
    json.NewEncoder(w).Encode(data)
}

// Обработчик CORS preflight
func corsHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
    w.WriteHeader(http.StatusOK)
}

func main() {
    // Создание тестового пользователя
    hashedPassword, _ := hashPassword("password123")
    users["testuser"] = User{
        ID:       1,
        Username: "testuser",
        Email:    "test@example.com",
        Password: hashedPassword,
    }
    userCounter = 2
    
    // Настройка маршрутов
    http.HandleFunc("/api/register", registerHandler)
    http.HandleFunc("/api/login", loginHandler)
    http.HandleFunc("/api/verify", verifyHandler)
    http.HandleFunc("/api/profile", authMiddleware(profileHandler))
    http.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
        sendJSONResponse(w, map[string]interface{}{
            "status":  "ok",
            "service": "auth-service",
            "version": "1.0.0",
        }, http.StatusOK)
    })
    
    // Обработчик CORS preflight
    http.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "OPTIONS" {
            corsHandler(w, r)
            return
        }
    })
    
    // Запуск сервера
    log.Println("Auth service starting on port 8080...")
    log.Println("Available endpoints:")
    log.Println("  POST   /api/register")
    log.Println("  POST   /api/login")
    log.Println("  GET    /api/verify?token=TOKEN")
    log.Println("  GET    /api/profile (requires auth)")
    log.Println("  GET    /api/health")
    
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal("Server error:", err)
    }
}
