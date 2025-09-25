package counter

import (
	"sync"
	"sync/atomic"
)

// 单个用户的上下行流量
type Counter struct {
	UpCounter   XrayTrafficCounter
	DownCounter XrayTrafficCounter
}

// 管理所有用户
type Manager struct {
	counters sync.Map // key: email(string), value: *Counter
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) GetCounter(email string) *Counter {
	val, ok := m.counters.Load(email)
	if ok {
		return val.(*Counter)
	}
	c := &Counter{
		UpCounter:   XrayTrafficCounter{V: &atomic.Int64{}},
		DownCounter: XrayTrafficCounter{V: &atomic.Int64{}},
	}
	m.counters.Store(email, c)
	return c
}
