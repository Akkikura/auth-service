package httpapi

import (
	"encoding/json"
	"net/http"
)

type errorEnvelope struct {
	Error errorBody `json:"error"`
}

type errorBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// ответы не храню в кеше браузера
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	// TODO ошибку Encode уже не вернуть потому что ответ начался
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, errorEnvelope{Error: errorBody{
		Code: code, Message: message, RequestID: requestIDFromContext(r.Context()),
	}})
}
