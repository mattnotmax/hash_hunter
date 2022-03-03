package Config

import (
	"github.com/fatih/color"
)

var R = color.New(color.FgRed)
var G = color.New(color.FgGreen)
var Y = color.New(color.FgYellow)

// config file name
var ConfigFile = "config.json"

// global API keys
var VirusTotal string
var HybridAnalysis string
var MalwareBazaar string
var Malshare string
var IntezerAnalyze string
var Maltiverse string
var Urlhaus string
var Triage string

// hash list
var Hashes = make([]string, 0)
