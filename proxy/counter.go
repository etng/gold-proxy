package proxy

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

type Counter struct {
	sync.RWMutex
	data map[string]int64
}

func NewCounter() *Counter {
	return &Counter{
		data: make(map[string]int64),
	}
}
func (c *Counter) Print() string {
	c.RLock()
	defer c.RUnlock()
	var keys []string
	for k, _ := range c.data {
		keys = append(keys, k)
	}
	var lines []string
	sort.Strings(keys)
	for _, k := range keys {
		lines = append(lines, fmt.Sprintf("%-50s %d", k, c.data[k]))
	}
	return strings.Join(lines, "\n")
}
func (c *Counter) Incr(name string, values ...int64) {
	var total int64 = 1
	if len(values) > 0 {
		total = 0
		for _, value := range values {
			total += value
		}
	}
	c.Lock()
	defer c.Unlock()
	c.data[name] = c.data[name] + total
}
