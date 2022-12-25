package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const PORT = 12356
const AddEndpoint = "https://%v/api/firewall/alias_util/add/%v"
const ListEndpoint = "https://%v/api/firewall/alias_util/list/%v"

type OPNSenseAliasBody struct {
	Address string `json:"address"`
}

type ListAliasResponse struct {
	Total    int `json:"total"`
	RowCount int `json:"rowCount"`
	Current  int `json:"current"`
	Rows     []struct {
		Ip string `json:"ip"`
	} `json:"rows"`
}

var client *http.Client
var ipRegexp *regexp.Regexp

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.URL.Query().Get("ip")
	valid := validateIP(ipAddress)
	if !valid {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	switch r.Method {
	case "GET":
		handleGetIPAuthorized(w, ipAddress)
	case "POST":
		handlePostIP(w, ipAddress)
	}
}

func handlePostIP(w http.ResponseWriter, ipAddress string) {
	log.Infof("Recieved request to add IP [%v] to authorized list", ipAddress)

	success := authorizeIP(ipAddress)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	log.Infof("Successfully authorized [%v]", ipAddress)
}

func handleGetIPAuthorized(w http.ResponseWriter, ipAddress string) {
	log.Infof("Recieved request to check IP [%v]", ipAddress)

	authorized, success := isIPAuthorized(ipAddress)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	if authorized {
		log.Infof("[%v] is authorized", ipAddress)
		w.Write([]byte("authorized"))
	} else {
		log.Infof("[%v] is not authorized", ipAddress)
		w.Write([]byte("unauthorized"))
	}
}

func validateIP(ip string) bool {
	return ipRegexp.MatchString(ip)
}

func authorizeIP(ip string) bool {
	aliasName := os.Getenv("ALIAS_NAME")
	address := os.Getenv("OPNSENSE_ADDR")
	endpoint := fmt.Sprintf(AddEndpoint, address, aliasName)
	body := &OPNSenseAliasBody{
		Address: ip,
	}
	marshaledBody, _ := json.Marshal(body)
	requestBody := bytes.NewBuffer(marshaledBody)
	response, err := sendOPNAPI(endpoint, "POST", requestBody)
	if err != nil {
		log.Errorf("Error sending authorize API request")
		return false
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		log.Errorf("Failed to send request (Code: %v): %v", response.StatusCode, response.Status)
		return false
	}
	responseBodyText, err := io.ReadAll(response.Body)
	if err != nil {
		log.Errorf("Error decoding response: %v", err)
		return false
	}
	s := string(responseBodyText)
	log.Infof("Response: %v", s)
	return true
}

func isIPAuthorized(ipAddress string) (bool, bool) {
	aliasName := os.Getenv("ALIAS_NAME")
	address := os.Getenv("OPNSENSE_ADDR")
	endpoint := fmt.Sprintf(ListEndpoint, address, aliasName)
	response, err := sendOPNAPI(endpoint, "GET", &bytes.Buffer{})
	if err != nil {
		log.Errorf("Error sending list API request")
		return false, false
	}
	defer response.Body.Close()
	listResponse := ListAliasResponse{}
	err = json.NewDecoder(response.Body).Decode(&listResponse)
	if err != nil {
		log.Errorf("Failed to decode list API response: %v", err)
		return false, false
	}
	ips := listResponse.Rows
	for _, row := range ips {
		if row.Ip == ipAddress {
			return true, true
		}
	}
	return false, true
}

func sendOPNAPI(endpoint string, method string, body *bytes.Buffer) (*http.Response, error) {
	request, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		log.Errorf("Error creating api GET request: %v", err)
		return nil, err
	}
	request.SetBasicAuth(os.Getenv("APIKEY"), os.Getenv("APIPASS"))
	if method == "POST" {
		request.Header.Add("Content-Type", "application/json")
	}
	log.Infof("Sending request to [%v]", endpoint)
	response, err := client.Do(request)
	if err != nil {
		log.Errorf("Error sending request: %v", err)
		return response, err
	}
	if response.StatusCode != 200 {
		log.Errorf("Failed to send request (Code: %v): %v", response.StatusCode, response.Status)
		return nil, err
	}
	return response, nil
}

func main() {
	ignoreCert := os.Getenv("IGNORE_CERT")
	if strings.EqualFold(ignoreCert, "true") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Transport: tr,
		}
	} else {
		client = &http.Client{}
	}
	ipRegexp = regexp.MustCompile("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.?\\b){4}$")

	log.Infof("Listing on port %v", PORT)
	http.HandleFunc("/", handleAPIRequest)
	err := http.ListenAndServe(fmt.Sprintf(":%v", PORT), nil)
	log.Fatalf("Error serving api: %v", err)
}
