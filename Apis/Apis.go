package Apis

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"hash_hunter/Config"

	"github.com/tidwall/gjson"
)

// Workhorse function for GET/POST requests with headers
func sendRequest(apiUrl string, client *http.Client, method string, header map[string]string, postParam io.Reader) ([]byte, error) {
	req, err := http.NewRequest(method, apiUrl, postParam)
	if err != nil {
		return nil, err
	}
	if len(header) != 0 { // check if header is empty, i.e none passed.
		for name, value := range header {
			req.Header.Add(name, value)
		}
	}
	response, http_err := client.Do(req)
	if http_err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Establish parms of HTTP client.
func httpClient() *http.Client {
	t := http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 100,
		DisableKeepAlives:   true,
	}
	client := http.Client{
		Transport: &t,
		Timeout:   7 * time.Second,
	}
	return &client
}

// GET request to Virus Total
func VirusTotal(hash string) {
	apiUrl := ("https://www.virustotal.com/api/v3/files/" + hash)
	header := make(map[string]string)
	header["x-apikey"] = Config.VirusTotal
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nVirus Total: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "error.code")
	if result.String() == "NotFoundError" {
		Config.R.Printf("\nVirus Total: Sample not found.")
	} else {
		malicious := gjson.Get(stringResponse, "data.attributes.last_analysis_stats.malicious")
		undetected := gjson.Get(stringResponse, "data.attributes.last_analysis_stats.undetected")
		Config.G.Printf("\nVirus Total: sample available. %v malicious, %v undetected.", malicious, undetected)
	}
}

// GET request to Hybrid Analysis
func HybridAnalysis(hash string) {
	apiUrl := ("https://www.hybrid-analysis.com/api/v2/overview/" + hash)
	header := make(map[string]string)
	header["api-key"] = Config.HybridAnalysis
	header["user-agent"] = "Falcon Sandbox"
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nHybrid Analysis: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "message")
	if result.String() == "Not Found" || result.String() == "Sorry, this hash was reported for abuse and is not available" {
		Config.R.Printf("\nHybrid Analysis: Sample not found.")
	} else {
		verdict := gjson.Get(stringResponse, "verdict")
		Config.G.Printf("\nHybrid Analysis: sample available. Verdict is %v.", verdict)
	}
}

// POST request to Malware Bazaar
func MalwareBazaar(hash string) {
	apiUrl := "https://mb-api.abuse.ch/api/v1/"
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	data := url.Values{}
	data.Set("query", "get_info")
	data.Set("hash", hash)
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodPost, header, strings.NewReader(data.Encode()))
	if err != nil {
		Config.R.Printf("\nMalware Bazaar: HTTP error, %v", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "query_status")
	if result.String() == "hash_not_found" {
		Config.R.Printf("\nMalware Bazaar: Sample not found.")
	} else if result.String() == "ok" {
		signature := gjson.Get(stringResponse, "data.0.signature")
		if signature.String() == "" {
			Config.G.Printf("\nMalware Bazaar: sample available.")
		} else {
			Config.G.Printf("\nMalware Bazaar: sample available. Recorded as %v.", signature)
		}
	}
}

// GET request to MalShare
func MalShare(hash string) {
	apiUrl := ("http://www.malshare.com/api.php?api_key=" + Config.Malshare + "&action=details&hash=" + hash)
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, nil, nil)
	if err != nil {
		Config.R.Printf("\nMalShare: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "ERROR.MESSAGE")
	if result.String() == "Sample not found" {
		Config.R.Printf("\nMalShare: Sample not found.")
	} else {
		available := gjson.Get(stringResponse, "SHA256")
		if available.String() == hash {
			Config.G.Printf("\nMalShare: sample available.")
		}
	}
}

// POST request to Intezer Analyze
func IntezerAnalyze(hash string) {
	apiUrl := "https://analyze.intezer.com/api/v2-0"
	tokenHeader := make(map[string]string)
	tokenHeader["Content-Type"] = "application/json; charset=UTF-8"

	// First get JWT token via API key. Need to pass API key in JSON byte slice.
	tokenUrl := apiUrl + "/get-access-token"
	jsonData := []byte(fmt.Sprintf(`{"api_key":"%v"}`, Config.IntezerAnalyze))
	c := httpClient()
	tokenResponse, err := sendRequest(tokenUrl, c, http.MethodPost, tokenHeader, bytes.NewBuffer(jsonData))
	if err != nil {
		Config.R.Printf("\nIntezer: HTTP error, %v", err)
		return
	}

	// now use JWT to make request in regards to the specific hash
	intezerToken := gjson.Get(string(tokenResponse), "result")
	header := make(map[string]string)
	bearer := "Bearer " + intezerToken.String()
	hashUrl := apiUrl + "/files/" + hash
	header["Authorization"] = bearer
	response, err := sendRequest(hashUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nIntezer: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "error")
	if result.String() == "Analysis was not found" {
		Config.R.Printf("\nIntezer: Sample not found.")
	} else if result.String() == "Analysis expired" {
		Config.R.Printf("\nIntezer: Request timeout or expired")
	} else {
		verdict := gjson.Get(stringResponse, "result.verdict")
		family := gjson.Get(stringResponse, "result.family_name")
		if family.String() == "" {
			Config.G.Printf("\nIntezer: sample available. Verdict is %v.", verdict)
		} else {
			Config.G.Printf("\nIntezer: sample available. Verdict is %v (%v).", verdict, family)
		}
	}
}

// GET request to Maltiverse
func Maltiverse(hash string) {
	apiUrl := ("https://api.maltiverse.com/sample/" + hash)
	header := make(map[string]string)
	header["Bearer"] = Config.Maltiverse
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nMaltiverse: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "message")
	if result.String() == "Not found" {
		Config.R.Printf("\nMaltiverse: Sample not found.")
	} else if result.String() == "Internal Server Error" || result.String() == "API quota limit exceeded" {
		Config.R.Printf("\nMaltiverse: Server Error / API limit.")
	} else {
		verdict := gjson.Get(stringResponse, "classification")
		Config.G.Printf("\nMaltiverse: sample available. Verdict is %v.", verdict)
	}
}

// GET request to InQuest
func InQuest(hash string) {
	apiUrl := ("https://labs.inquest.net/api/dfi/details?sha256=" + hash)
	header := make(map[string]string)
	header["Authorization"] = "Basic null"
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nInQuest: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "success")
	if result.String() == "false" {
		Config.R.Printf("\nInQuest: Sample not found.")
	} else {
		verdict := gjson.Get(stringResponse, "data.classification")
		Config.G.Printf("\nInQuest Labs: sample available. Verdict is %v.", strings.ToLower(verdict.String()))
	}
}

// POST Request to URLHaus
func Urlhaus(hash string) {
	apiUrl := ("https://urlhaus-api.abuse.ch/v1/payload/")
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	data := url.Values{}
	data.Set("sha256_hash", hash)
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodPost, header, strings.NewReader(data.Encode()))
	if err != nil {
		Config.R.Printf("\nURLHaus: HTTP error, %v", err)
		return
	}
	stringResponse := string(response)
	result := gjson.Get(stringResponse, "query_status")
	if result.String() == "no_results" {
		Config.R.Printf("\nURLHaus: Sample not found.")
	} else if result.String() == "ok" {
		signature := gjson.Get(stringResponse, "signature")
		if signature.String() == "" {
			fmt.Printf("\nURLHaus: sample available.")
		} else {
			fmt.Printf("\nURLHaus: sample available. Recorded as %v", signature)
		}
	}
}

// GET request to Tri.age
func Triage(hash string) {
	apiUrl := ("https://api.tria.ge/v0/search?query=sha256:" + hash)
	header := make(map[string]string)
	bearer := ("Bearer " + Config.Triage)
	header["Authorization"] = bearer
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nTri.age: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	check := gjson.Get(stringResponse, "data.0")
	if len(check.String()) == 0 {
		Config.R.Printf("\nTri.age: Sample not found.")
	} else {
		result := gjson.Get(stringResponse, "data.0.id")
		Config.G.Printf("\nTri.age: sample available (id: %v)", result)
	}
}

// GET request to NSRL hashlookup
func Hashlookup(hash string) {
	apiUrl := ("https://hashlookup.circl.lu/lookup/sha256/" + hash)
	header := make(map[string]string)
	header["Content-Type"] = "application/json"
	c := httpClient()
	response, err := sendRequest(apiUrl, c, http.MethodGet, header, nil)
	if err != nil {
		Config.R.Printf("\nNSRL Hashlookup: HTTP error, %v.", err)
		return
	}
	stringResponse := string(response)
	check := gjson.Get(stringResponse, "message")
	if check.String() == "Non existing SHA-256" {
		Config.R.Printf("\nNSRL Hashlookup: Sample not found.")
	} else {
		result := gjson.Get(stringResponse, "FileName")
		Config.G.Printf("\nNSRL Hashlookup: name: %v", result)
	}
}
