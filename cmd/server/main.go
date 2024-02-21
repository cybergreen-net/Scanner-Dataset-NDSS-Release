package main

import (
	"Scanner/pkg/config"
	pserver "Scanner/pkg/policy-cache-server"
	"Scanner/pkg/scanner/structs"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/publicsuffix"
)

const DNS_CACHE_REFRESH_MINUTE_COUNT = 10
const MX_LOCK_IN_COUNT = 5

type Server struct {
	mutex        sync.Mutex
	Tree         pserver.IPPrefixTree
	DNSCache     pserver.RecordCache
	MXScanCache  pserver.RecordCache
	MXCacheCount int
	TLDList      pserver.TLDList
	Capabilities config.Capabilities
}

func (s *Server) handleGetMsg(c *gin.Context) {
	tld := c.Query("tld")
	recordType, err := strconv.Atoi(c.Query("type"))
	if err != nil {
		panic("couldn't parse query type")
	}

	if tld != "." {
		tld = strings.Trim(tld, ".")
		suff, _ := publicsuffix.PublicSuffix(tld)

		if suff != strings.Trim(tld, ".") {
			c.Data(404, "binary", make([]byte, 0))
			return
		}
		tld = suff
	}

	bytes, err := s.DNSCache.Cache.Get(fmt.Sprintf("%s-%d", tld, recordType))
	// cache hit
	if err == nil {
		c.Data(200, "binary", bytes)
		return
	}
	// cache miss
	s.TLDList.AddToTLDList(tld)

	// c.Data(200, "binary", LookupStoreMsg(tld, uint16(recordType), *s.Cache.Cache))
	c.Data(404, "binary", make([]byte, 0))
}

func (s *Server) handleIPFilterCheck(c *gin.Context) {
	ip := c.Query("ip")
	if _, exists, err := s.Tree.Tree.GetByString(ip); err == nil && exists {
		c.String(200, "true")
	} else {
		c.String(200, "false")
	}
}

func (s *Server) handleGetMX(c *gin.Context) {
	mx := c.Param("mx")
	cachedMXBytes, err := s.MXScanCache.Cache.Get(mx)
	if err != nil {
		c.String(400, "cache miss: no entry")
	} else {
		// Check that cache result is 'locked in'
		var cachedMX structs.MXSpecificData
		_ = json.Unmarshal(cachedMXBytes, &cachedMX)
		if cachedMX.SeenCount < MX_LOCK_IN_COUNT {
			c.String(400, fmt.Sprintf("cache miss: staged mx but not locked in (%d/%d)",
				cachedMX.SeenCount,
				MX_LOCK_IN_COUNT))
		} else {
			c.Data(200, "binary", cachedMXBytes)
		}
	}
}

func (s *Server) handlePutMX(c *gin.Context) {
	mx := c.Param("mx")
	newMXBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.String(500, fmt.Sprintf("could not read bytes: %s", err.Error()))
	}
	var cachedMX structs.MXSpecificData
	var newMX structs.MXSpecificData
	// Err on unmarshaling public key, fix later
	err = json.Unmarshal(newMXBytes, &newMX)
	if err != nil {
		panic(err)
	}
	if cachedMXBytes, err := s.MXScanCache.Cache.Get(mx); err != nil {
		// Cache MX if not previously cached already
		newMX.SeenCount = 1
		newMXBytes, _ = json.Marshal(newMX)
		s.MXScanCache.Cache.Set(mx, newMXBytes)
		if newMX.SeenCount == MX_LOCK_IN_COUNT {
			s.mutex.Lock()
			s.MXCacheCount++
			s.mutex.Unlock()
		}
		c.String(200, fmt.Sprintf("successfully cached: %s", mx))
	} else {
		_ = json.Unmarshal(cachedMXBytes, &cachedMX)
		if cachedMX.SeenCount == MX_LOCK_IN_COUNT {
			c.String(300, fmt.Sprintf("already cached: %s", mx))
		} else {
			// If cached MX is not 'locked in,' then compare incoming MX and cached MX
			compareRes := cachedMX.CompareTo(newMX)
			if compareRes < 0 {
				// Replace current MX with new MX
				s.MXScanCache.Cache.Set(mx, newMXBytes)
				c.String(200, fmt.Sprintf("replaced cached: %s", mx))
			} else {
				cachedMX.SeenCount += 1
				cachedMXBytes, _ = json.Marshal(cachedMX)
				s.MXScanCache.Cache.Set(mx, cachedMXBytes)
				// Increment total number of locked in cached records
				if cachedMX.SeenCount == MX_LOCK_IN_COUNT {
					s.mutex.Lock()
					s.MXCacheCount++
					s.mutex.Unlock()
				}
				c.String(200, fmt.Sprintf("incremented staged MX: %s (%d/%d)", mx, cachedMX.SeenCount, MX_LOCK_IN_COUNT))
			}
		}
	}
}

func (s *Server) handleCapabilitiesRequest(c *gin.Context) {
	c.JSON(200, s.Capabilities)
}

func (s *Server) handleGetMXCount(c *gin.Context) {
	c.String(200, fmt.Sprintf("%d", s.MXCacheCount))
}

func (s *Server) cacheRemoveCallback(key string, entry []byte) {
	var cachedMX structs.MXSpecificData
	_ = json.Unmarshal(entry, &cachedMX)
	if cachedMX.SeenCount == MX_LOCK_IN_COUNT {
		s.MXCacheCount--
	}
}

func (s *Server) PeriodicCacheRefresh(refreshDelay time.Duration) {
	for range time.Tick(refreshDelay) {
		pserver.PopulateCache(s.TLDList.TLDs, *s.DNSCache.Cache)
	}
}

func main() {
	serverState := Server{}
	dnsCache := pserver.NewCache(15*time.Minute, nil)
	mxCache := pserver.NewCache(10*time.Hour, serverState.cacheRemoveCallback)
	tree := pserver.NewTree("")
	tldList := pserver.NewTLDList("")
	capabilities := config.IdentifyCapabilities()

	fmt.Printf("Server is starting up... Please wait until cache populates.")
	pserver.PopulateCache(tldList.TLDs, *dnsCache.Cache)
	fmt.Printf("Server Ready.\n")

	serverState.DNSCache = dnsCache
	serverState.MXScanCache = mxCache
	serverState.Tree = tree
	serverState.TLDList = tldList
	serverState.Capabilities = capabilities

	server := gin.Default()
	server.GET("/get-msg", serverState.handleGetMsg)
	server.GET("/restricted-ip", serverState.handleIPFilterCheck)
	server.GET("/", serverState.handleCapabilitiesRequest)
	server.GET("/get-mx/:mx", serverState.handleGetMX)
	server.POST("/put-mx/:mx", serverState.handlePutMX)
	server.GET("/get-mx-count", serverState.handleGetMXCount)

	go serverState.PeriodicCacheRefresh(DNS_CACHE_REFRESH_MINUTE_COUNT * time.Minute)

	if err := server.Run(); err != nil {
		panic("failed to run a server at localhost")
	}
}
