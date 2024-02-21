package policy_cache_server

import (
	"fmt"
	"github.com/zmap/go-iptree/iptree"
	"log"
	"net"
	"os"
	"strings"
)

const DEFAULT_FILTER_PATH = "dataset/unscanned_ips.txt"

type IPPrefixTree struct {
	Tree *iptree.IPTree
}

func checkIPorCIDR(ipString string) bool {
	_, _, err := net.ParseCIDR(ipString)
	if err == nil {
		return true
	}
	ip := net.ParseIP(ipString)
	if ip != nil {
		return true
	}
	return false
}

func ProcessTreeFromList(split []string) (IPPrefixTree, []string) {
	tree := iptree.New()
	ignoredEntries := make([]string, 0)
	for _, ip := range split {
		trimmedIPString := strings.TrimSpace(ip)
		if checkIPorCIDR(trimmedIPString) {
			fmt.Printf("Adding IP: %v\n", trimmedIPString)
			tree.AddByString(trimmedIPString, 0)
		} else {
			ignoredEntries = append(ignoredEntries, ip)
		}
	}
	return IPPrefixTree{Tree: tree}, ignoredEntries
}

func NewTree(datasetPath string) IPPrefixTree {
	if len(strings.TrimSpace(datasetPath)) == 0 {
		log.Printf("Using the default filter list since no dataset was provided. %v\n", DEFAULT_FILTER_PATH)
		datasetPath = DEFAULT_FILTER_PATH
	}
	data, err := os.ReadFile(datasetPath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(-1)
	}

	split := strings.Split(string(data), "\n")

	tree, _ := ProcessTreeFromList(split)

	return tree
}
