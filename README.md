# Hash Hunter  

A simple, multithreaded program for finding if a hash exists on various malware/hash repositories. No more, no less. Useful if you just want to check where a sample might be available. 

Currently implemented 
- Virus Total (paid API required)
- Hybrid Analysis (registration required)
- MalShare (registration required)
- Malware Bazaar (registration required)
- Intezer (registration required)
- Maltiverse (registration required)
- URLHaus (Twitter account required)
- Tri.age (Researcher account required)
- InQuest Labs (free tier limited to 1337 queries per day)
- Hashlookup (free)

## Usage 

```
no flag
    manually enter SHA256 hashes.
-f <path/to/file> 
    List of SHA256 hashes separated by carriage return.  
```


## Dependencies

Enter your API keys for each service, if required. If you do not have an API key then simple leave as `""`.  

Add these to a config file `config.json` as per below:  

```
{"virusTotal":"KEY",
"hybridAnalysis":"KEY",
"malwareBazaar":"KEY",
"malshare":"KEY",
"maltiverse":"KEY",
"urlhaus":"KEY",
"triage":"KEY",
"intezerAnalyze":"KEY"}
```

If you are going to build from source you'll also need the below module for JSON parsing. 

```
go get github.com/tidwall/gjson
```

## Sample Output

```
PS C:\hash_hunter.exe     

[*] Config file OK.
Enter SHA256 hashes. Press ENTER to finish.
hash: 20afc142a26c094db25ede02fc13e99acc4a4431db32ecd2d3be05b9e3f852bc
hash: 

20afc142a26c094db25ede02fc13e99acc4a4431db32ecd2d3be05b9e3f852bc
Hybrid Analysis: sample available. Verdict is malicious.
Maltiverse: Sample not found.
Tri.age: available (id: 220204-3z9qnafhal)
URLHaus: Not found
NSRL Hashlookup: Sample not found.
Malware Bazaar: Sample not found.
InQuest: Sample not found.
Virus Total: sample available. 34 malicious, 22 undetected.
Intezer: Sample not found.
MalShare: Sample not found.

Hash Hunter completed. Search took 2.7975446s
```

The order returned is based on the API latency and may differ each time.  