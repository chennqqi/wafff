package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

var (
	accesslog string
)

type LogLine struct {
	UserAgent       string
	Referer         string
	Path            string
	Method          string
	Protocol        string
	SizeOrSomething string
	ResponseCode    string
}

func createWafRule(l LogLine) {
	interesting := false
	interestingSection := "REQUEST_URI"
	interestingExtra := ""
	// Define some properties of interesting requests
	if strings.Contains(l.Path, "<") {
		interesting = true
	}
	if len(l.Path) > 40 {
		interesting = true
	}
	if strings.Contains(l.Path, "script") {
		interesting = true
	}
	if strings.Contains(l.Path, "alert") {
		interesting = true
	}
	if l.Referer != "-" {
		if strings.Contains(strings.ToLower(l.Referer), "nikto") || strings.Contains(strings.ToLower(l.Referer), "acunetix") {
			interestingSection = "REQUEST_HEADERS"
			interestingExtra = ":Referer"
		}
	}
	if interesting {
		fmt.Println(fmt.Sprintf("SecRule %s%s \"%s\" \"drop,msg:'Blocked something',id:'something-or-other',phase:0", interestingSection, interestingExtra, l.Path))
	}
}
func main() {
	flag.StringVar(&accesslog, "f", "", "-f=filename")
	flag.Parse()
	if accesslog == "" {
		log.Fatalf("Requires a filename\n")
	}

	//54.208.242.36 - - [29/Jan/2016:21:48:23 +0000]
	re, err := regexp.Compile(`.* .* .* \[.*\] "(.*) (.*) (.*)" (\d+) (\d+) "(.*)" "(.*)"`)
	if err != nil {
		log.Fatalf("Could not compile: %s", err.Error())
	}
	f, err := os.Open(accesslog)
	if err != nil {
		log.Fatalf("Could not open file: %s", err.Error())
	}

	bufReader := bufio.NewReader(f)
	for {
		l, isPrefix, err := bufReader.ReadLine()
		if err != nil {
			break
		}
		if isPrefix {
			log.Printf("line Skipped due to prefix being found: %s", l)
			continue
		}

		//logline := processLog(l)
		res := re.FindAllStringSubmatch(string(l), -1)
		if len(res) != 1 {
			log.Printf("We had issues parsing this: %s", l)
			continue
		}
		parsedLine := res[0]
		ll := LogLine{
			UserAgent:       parsedLine[7],
			Referer:         parsedLine[6],
			Path:            parsedLine[2],
			Method:          parsedLine[1],
			Protocol:        parsedLine[3],
			SizeOrSomething: parsedLine[5],
			ResponseCode:    parsedLine[4],
		}
		createWafRule(ll)
	}
}
