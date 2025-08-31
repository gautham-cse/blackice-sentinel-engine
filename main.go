package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

type Message struct {
	Type            string `json:"type"`
	From            string `json:"from"`
	To              string `json:"to"`
	SessionID       string `json:"sessionID"`
	EphemeralPubKey string `json:"ephemeralPubKey"`
}

type Client struct {
	UserID       string
	Conn         *websocket.Conn
	LastActivity time.Time
}

var (
	clients  = sync.Map{}
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	rateLimit = make(map[string]time.Time)
	rateMutex = sync.Mutex{}
)

func verifyJWT(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return jwtSecret, nil
	})
	if err != nil {
		return "", err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		userID, ok := claims["userID"].(string)
		if !ok {
			return "", jwt.ErrTokenInvalidClaims
		}
		return userID, nil
	}
	return "", jwt.ErrTokenInvalidClaims
}

func allowed(userID string) bool {
	rateMutex.Lock()
	defer rateMutex.Unlock()
	if t, ok := rateLimit[userID]; ok {
		if time.Since(t) < 50*time.Millisecond {
			return false
		}
	}
	rateLimit[userID] = time.Now()
	return true
}

func sendToClient(to string, msg Message) error {
	c, ok := clients.Load(to)
	if !ok {
		return nil
	}
	client := c.(*Client)
	return client.Conn.WriteJSON(msg)
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}
	defer conn.Close()

	_, msg, err := conn.ReadMessage()
	if err != nil {
		return
	}
	var auth struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(msg, &auth); err != nil {
		return
	}

	userID, err := verifyJWT(auth.Token)
	if err != nil {
		log.Println("JWT verification failed:", err)
		conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "Unauthorized"))
		return
	}

	client := &Client{
		UserID:       userID,
		Conn:         conn,
		LastActivity: time.Now(),
	}
	clients.Store(userID, client)
	log.Println("Client registered:", userID)

	defer func() {
		clients.Delete(userID)
		log.Println("Client disconnected:", userID)
	}()

	for {
		var msg Message
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("Read error:", err)
			break
		}

		client.LastActivity = time.Now()

		if !allowed(userID) {
			log.Println("Rate limit exceeded for:", userID)
			continue
		}

		switch msg.Type {
		case "INVITE", "ACCEPT", "END_CALL":
			if err := sendToClient(msg.To, msg); err != nil {
				log.Println("Forward error:", err)
			}
		default:
			log.Println("Unknown message type from", userID)
		}
	}
}

func getJWTHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("user")
	if userID == "" {
		http.Error(w, "Missing user parameter", http.StatusBadRequest)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"userID": userID,
		"exp":    time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	w.Write([]byte(tokenString))
}

func main() {
	port := "8080"
	if p := os.Getenv("PORT"); p != "" {
		port = p
	}

	http.Handle("/", http.FileServer(http.Dir("./public"))) // serve test.html
	http.HandleFunc("/ws", wsHandler)
	http.HandleFunc("/get_jwt", getJWTHandler) // auto JWT endpoint

	// Production-ready: let hosting platform handle TLS
	log.Println("BSP signaling server running on port", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
