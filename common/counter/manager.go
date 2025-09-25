package counter

import (
	"sync"
)

// Manager 管理所有用户的流量计数器
type Manager struct {
	mu        sync.RWMutex
	counters  map[string]*TrafficCounter
}

// TrafficCounter 保存单个用户的上下行统计
type TrafficCounter struct {
	UpCounter   Counter
	DownCounter Counter
}

func NewManager() *Manager {
	return &Manager{
		counters: make(map[string]*TrafficCounter),
	}
}

// GetCounter 返回指定用户的流量计数器，如果不存在就新建
func (m *Manager) GetCounter(email string) *TrafficCounter {
	m.mu.RLock()
	if tc, ok := m.counters[email]; ok {
		m.mu.RUnlock()
		return tc
	}
	m.mu.RUnlock()

	m.mu.Lock()
	defer m.mu.Unlock()
	// double-check
	if tc, ok := m.counters[email]; ok {
		return tc
	}

	tc := &TrafficCounter{
		UpCounter:   &XrayTrafficCounter{V: new(int64)},
		DownCounter: &XrayTrafficCounter{V: new(int64)},
	}
	m.counters[email] = tc
	return tc
}

// ResetCounter 清零某个用户的计数器
func (m *Manager) ResetCounter(email string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tc, ok := m.counters[email]; ok {
		tc.UpCounter.Set(0)
		tc.DownCounter.Set(0)
	}
}

// GetAll 返回所有用户的流量计数器
func (m *Manager) GetAll() map[string]*TrafficCounter {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]*TrafficCounter, len(m.counters))
	for k, v := range m.counters {
		result[k] = v
	}
	return result
}
