package policy_cache_server

import (
	"fmt"
	"os"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/cheggaaa/pb/v3"
	"github.com/miekg/dns"
)

const (
	DefaultResolver = "1.1.1.1:53"
	WORKER_COUNT    = 50
)

type RecordCache struct {
	Cache *bigcache.BigCache
}

type LookupTask struct {
	TLD        string
	LookupType uint16
}

type cacheRemoveCallback func(key string, entry []byte)

func NewCache(expireTime time.Duration, cb cacheRemoveCallback) RecordCache {
	ctx := bigcache.DefaultConfig(expireTime)
	ctx.OnRemove = cb
	cache, err := bigcache.NewBigCache(ctx)
	if err != nil {
		fmt.Println("failed to spin up cache. Exiting...")
		os.Exit(-1)
	}
	return RecordCache{Cache: cache}
}

func PopulateCache(tldList []string, c bigcache.BigCache) {
	fmt.Println("Initializing Caches ... Please wait.")

	tasks := make([]LookupTask, 0)
	for _, tld := range tldList {
		// edge case
		if tld == "" {
			continue
		}
		if tld == "." {
			tasks = append(tasks, LookupTask{TLD: tld, LookupType: dns.TypeDS})
			tasks = append(tasks, LookupTask{TLD: tld, LookupType: dns.TypeNS})
			tasks = append(tasks, LookupTask{TLD: tld, LookupType: dns.TypeDNSKEY})
		} else {
			tasks = append(tasks, LookupTask{TLD: tld, LookupType: dns.TypeNS})
			tasks = append(tasks, LookupTask{TLD: tld, LookupType: dns.TypeDNSKEY})
		}
	}
	taskChan := make(chan LookupTask, len(tasks))
	doneChan := make(chan struct{}, len(tasks))
	// create workers
	for i := 0; i < WORKER_COUNT; i++ {
		go Worker(c, taskChan, doneChan)
	}
	// populate task channel
	for _, t := range tasks {
		taskChan <- t
	}
	bar := pb.StartNew(len(tasks))
	for i := 0; i < len(tasks); i++ {
		<-doneChan
		bar.Increment()
	}
	bar.Finish()
}

func Worker(c bigcache.BigCache, tasks <-chan LookupTask, done chan<- struct{}) {
	for t := range tasks {
		LookupStoreMsg(t.TLD, t.LookupType, c)
		done <- struct{}{}
	}
}

func LookupStoreMsg(tld string, qType uint16, c bigcache.BigCache) []byte {
	msg := MakeDNSQuery(tld, qType)
	msg, err := dns.Exchange(msg, DefaultResolver)
	if err != nil {
		return make([]byte, 0)
	}

	bytes := ConvertToByte(msg)

	if len(msg.Answer) == 0 {
		// Don't set the cache on empty responses.
		return bytes
	}

	c.Set(fmt.Sprintf("%s-%d", tld, qType), bytes)

	return bytes
}
