package oauth

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockClient struct {
	GetFunc func(req string) (*http.Response, error)
}

var (
	GetGetFunc func(req string) (*http.Response, error)
)

func (m *MockClient) Get(req string) (*http.Response, error) {
	return GetGetFunc(req)
}
func TestGetAccessTokenSuccess(t *testing.T) {
	client = &MockClient{}
	GetGetFunc = func(string) (*http.Response, error) {
		responseBody := io.NopCloser(bytes.NewReader([]byte(`{"id":"123","user_id": 1, "client_id": 2}`)))
		return &http.Response{
			StatusCode: 200,
			Body:       responseBody,
		}, nil
	}
	result, err := getAccessToken("123")
	assert.Nil(t, err)
	assert.Equal(t, int64(2), result.ClientId)
	assert.Equal(t, int64(1), result.UserId)
	assert.Equal(t, "123", result.Id)
}

func TestGetAccessTokenError(t *testing.T) {
	client = &MockClient{}
	GetGetFunc = func(string) (*http.Response, error) {
		responseBody := io.NopCloser(bytes.NewReader([]byte(`{"error": "not found"}`)))
		return &http.Response{
			StatusCode: 404,
			Body:       responseBody,
		}, nil
	}
	_, err := getAccessToken("123")
	assert.Equal(t, "not found", err.GetMessage())
}
