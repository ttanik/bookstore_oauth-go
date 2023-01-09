package oauth

import (
	"encoding/json"
	"errors"
	"io"

	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/ttanik/bookstore_utils-go/rest_errors"
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	baseURL          = "http://localhost:8080"
	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.GetStatus() == http.StatusNotFound {
			return nil
		}
		return err
	}
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response, err := http.Get(baseURL + fmt.Sprintf("/oauth/access_token/%s", accessTokenId))
	if err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to create request ", errors.New("http client error"))
	}
	if response == nil || response.Body == nil {
		return nil, rest_errors.NewInternalServerError("invalid restclient response when trying to get access token", errors.New("request error"))
	}

	if response.StatusCode > 299 {
		if response.StatusCode == http.StatusNotFound {
			return nil, rest_errors.NewNotFoundError("not found")
		}
		return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", errors.New("not found error"))

	}
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, rest_errors.NewInternalServerError("invalid response", errors.New("http client error"))
	}

	defer response.Body.Close()
	var at accessToken
	if err := json.Unmarshal(bytes, &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("json format error"))
	}
	return &at, nil
}
