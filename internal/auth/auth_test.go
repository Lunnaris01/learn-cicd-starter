package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyWrongAuthentificationHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "http://boot.dev", nil)
	bad_header := req.Header
	key, err := GetAPIKey(bad_header)
	if err == nil || err.Error() != "no authorization header included" {
		t.Fatalf("Expected err: %s but got %v instead", "no authorization header included", err.Error())
	}
	if key != "" {
		t.Fatalf("Expected empty String but got Key: %v", key)
	}

	req.Header.Add("Authorization", "Blabliblubb")
	key, err = GetAPIKey(bad_header)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("Expected err: %s but got %v instead", "malformed authorization header", err.Error())
	}
	if key != "" {
		t.Fatalf("Expected empty String but got Key: %v", key)
	}

}

func TestGetAPICorrectHeader(t *testing.T) {
	req, err := http.NewRequest("GET", "http://boot.dev", nil)
	bad_header := req.Header
	apikey := "myApiKey"
	req.Header.Add("Authorization", "ApiKey "+apikey)
	key, err := GetAPIKey(bad_header)
	if err != nil {
		t.Fatalf("Expected err to be nil got %v instead", err.Error())
	}
	if key != apikey {
		t.Fatalf("Expected key to be: %s\nBut got key: %v", apikey, key)
	}

}

func TestGetAPIApiKeyWithWhitespace(t *testing.T) {
	req, err := http.NewRequest("GET", "http://boot.dev", nil)
	bad_header := req.Header
	apikey := "myApiKey is very special!"
	req.Header.Add("Authorization", "ApiKey "+apikey)
	key, err := GetAPIKey(bad_header)
	if err != nil {
		t.Fatalf("Expected err to be nil got %v instead", err.Error())
	}
	if key != "myApiKey" {
		t.Fatalf("Expected key to be: %s\nBut got key: %v", "myApiKey", key)
	}

}

func TestGetAPIApiKeyWithoutWhitespace(t *testing.T) {
	req, err := http.NewRequest("GET", "http://boot.dev", nil)
	bad_header := req.Header
	apikey := "myApiKey"
	req.Header.Add("Authorization", "ApiKey"+apikey)
	key, err := GetAPIKey(bad_header)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Fatalf("Expected err: %s but got %v instead", "malformed authorization header", err.Error())
	}
	if key != "" {
		t.Fatalf("Expected empty String but got Key: %v", key)
	}

}
