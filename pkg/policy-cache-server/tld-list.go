package policy_cache_server

import (
	"fmt"
	"log"
	"os"
	"strings"
)

const DEFAULT_TLD_PATH = "dataset/cached_tlds.txt"

type TLDList struct {
	TLDs []string
	Path string
}

func NewTLDList(datasetPath string) TLDList {
	tldList := TLDList{}

	if len(strings.TrimSpace(datasetPath)) == 0 {
		log.Printf("Using the default domain cache list since no dataset was provided. %v\n", DEFAULT_TLD_PATH)
		tldList.Path = DEFAULT_TLD_PATH
	} else {
		tldList.Path = datasetPath
	}

	data, err := os.ReadFile(tldList.Path)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	l := make([]string, 0)
	split := strings.Split(string(data), "\n")
	for _, tld := range split {
		l = append(l, tld)
	}
	tldList.TLDs = l
	return tldList
}

// Adds TLD if new, adds to file on disk. Returns true if TLD is new
func (t *TLDList) AddToTLDList(tld string) bool {
	for _, s := range t.TLDs {
		if tld == s {
			return false
		}
	}
	t.TLDs = append(t.TLDs, tld)
	f, err := os.OpenFile(t.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}
	defer f.Close()

	if _, err = f.Write([]byte(tld + "\n")); err != nil {
		panic(err)
	}

	return true
}
