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
const ENDPOINT = "https://%v/api/firewall/alias_util/add/%v"

type OPNSenseAliasBody struct {
	Address string `json:"address"`
}

var client *http.Client
var ipRegexp *regexp.Regexp

func handleAPIRequest(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.URL.Query().Get("ip")
	log.Infof("Recieved request to add IP [%v] to authorized list", ipAddress)
	valid := validateIP(ipAddress)
	if !valid {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	success := authorizeIP(ipAddress)
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	log.Infof("Successfully authorized [%v]", ipAddress)
}

func validateIP(ip string) bool {
	return ipRegexp.MatchString(ip)
}

func authorizeIP(ip string) bool {
	aliasName := os.Getenv("ALIAS_NAME")
	address := os.Getenv("OPNSENSE_ADDR")
	endpoint := fmt.Sprintf(ENDPOINT, address, aliasName)
	body := &OPNSenseAliasBody{
		Address: ip,
	}
	marshaledBody, _ := json.Marshal(body)
	requestBody := bytes.NewBuffer(marshaledBody)
	request, err := http.NewRequest("POST", endpoint, requestBody)
	if err != nil {
		log.Errorf("Error creating api POST request: %v", err)
		return false
	}
	request.Header.Add("Content-Type", "application/json")
	request.SetBasicAuth(os.Getenv("APIKEY"), os.Getenv("APIPASS"))
	log.Infof("Sending request to [%v] with body %v", endpoint, body)
	response, err := client.Do(request)
	if err != nil {
		log.Errorf("Error sending request: %v", err)
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
