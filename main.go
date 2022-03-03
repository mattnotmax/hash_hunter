package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"hash_hunter/Apis"
	"hash_hunter/Config"
	"sync"
	"time"
)

func main() {
	var hashListFile = flag.String("f", "", "Path to text file containing SHA256 hashes (one per line).")
	flag.Usage = usage
	flag.Parse()
	fmt.Println(*hashListFile)

	// Check config file & read API Keys
	checkConfig()
	loadConfig()

	// branch to manual entry or read the text file
	if *hashListFile != "" {
		openFile(*hashListFile)
	} else {
		manualEntry()
	}
	// start stopwatch
	defer timeTrack(time.Now())
	checkHashes()
}

// prints help usage
func usage() {
	Config.Y.Fprintf(flag.CommandLine.Output(), "\nHash Hunter: Locate malware samples with ease.\n")
	fmt.Fprintf(flag.CommandLine.Output(), "API keys are required in 'config.json' file in same directory.\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Default: Enter SHA256 hashes manually.\nOptional:")
	flag.PrintDefaults()
}

// loop through API checks for each hash
func checkHashes() {
	for _, hash := range Config.Hashes {
		var waitgroup sync.WaitGroup
		Config.Y.Printf("\n\n%v", hash)
		if Config.VirusTotal != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.VirusTotal(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.HybridAnalysis != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.HybridAnalysis(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.MalwareBazaar != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.MalwareBazaar(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.Malshare != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.MalShare(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.IntezerAnalyze != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.IntezerAnalyze(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.Maltiverse != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.Maltiverse(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.Urlhaus != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.Urlhaus(hash)
				waitgroup.Done()
			}(hash)
		}
		if Config.Triage != "" {
			waitgroup.Add(1)
			go func(hash string) {
				Apis.Triage(hash)
				waitgroup.Done()
			}(hash)
		}
		waitgroup.Add(1)
		go func(hash string) {
			Apis.InQuest(hash)
			waitgroup.Done()
		}(hash)
		waitgroup.Add(1)
		go func(hash string) {
			Apis.Hashlookup(hash)
			waitgroup.Done()
		}(hash)
		waitgroup.Wait()
	}
}

// checks the existance of the config file
func checkConfig() {
	exe, err := os.Executable()
	if err != nil {
		panic(err)
	}
	exePath := filepath.Dir(exe) + "\\" + Config.ConfigFile
	if fileExists(exePath) {
		Config.Y.Printf("[*] Config file OK.\n")
	} else {
		Config.R.Printf("[!] Cannot find config file.")
		os.Exit(1)
	}
}

// generic file exists check
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// gets API keys for each malware service. Populates global variables.
func loadConfig() {
	config := readConfig(Config.ConfigFile)
	Config.VirusTotal = config["virusTotal"]
	Config.HybridAnalysis = config["hybridAnalysis"]
	Config.MalwareBazaar = config["malwareBazaar"]
	Config.Malshare = config["malshare"]
	Config.IntezerAnalyze = config["intezerAnalyze"]
	Config.Maltiverse = config["maltiverse"]
	Config.Urlhaus = config["urlhaus"]
	Config.Triage = config["triage"]
}

// reads config file. Returns map of API keys.
func readConfig(filename string) map[string]string {
	file, err := os.Open(filename)
	if err != nil {
		Config.R.Printf("[!] Cannot open %s: %s", Config.ConfigFile, err)
		os.Exit(1)
	}
	defer file.Close()
	var data map[string]string
	if err := json.NewDecoder(file).Decode(&data); err != nil {
		Config.R.Printf("[!] Cannot read %s: %s", Config.ConfigFile, err)
		os.Exit(1)
	}
	return data
}

// gets hash list from hash list file. Sends each hash to check validity.
func openFile(hashListFile string) {
	if !fileExists(hashListFile) {
		Config.R.Println("[!] Cannot find hash list file.")
		os.Exit(1)
	}
	file, err := os.Open(hashListFile)
	if err != nil {
		Config.R.Println("[!] Cannot open hash list file.")
		os.Exit(1)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	Config.Y.Println("[*] Checking SHA256 hash list...")
	for scanner.Scan() {
		// check hashes
		if !verifySha256(scanner.Text()) {
			Config.R.Printf("\n[!] %s is invalid. Discarding.", scanner.Text())
		} else {
			Config.Y.Printf("\n[*] %s is valid.", scanner.Text())
			Config.Hashes = append(Config.Hashes, scanner.Text())
		}

	}
	if err := scanner.Err(); err != nil {
		Config.R.Println("[!] Cannot read hash list file.")
		os.Exit(1)
	}
}

// check validity of SHA256
func verifySha256(hash string) bool {
	valid, _ := regexp.MatchString("^[A-Fa-f0-9]{64}$", hash)
	return valid
}

// manual entry of SHA256 hashes
func manualEntry() {
	scanner := bufio.NewScanner(os.Stdin)
	Config.Y.Println("Enter SHA256 hashes. Press ENTER to finish.")
	for {
		Config.Y.Print("hash: ")
		scanner.Scan()
		manualHash := scanner.Text()
		if len(manualHash) != 0 {
			if verifySha256(manualHash) {
				Config.Hashes = append(Config.Hashes, manualHash)
			} else {
				Config.R.Printf("[*] %s is invalid. Discarding.\n", manualHash)
			}
		} else {
			break
		}
	}
}

// measure time to check APIs
func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	Config.Y.Printf("\n\nHash Hunter completed. Search took %s", elapsed)
}
