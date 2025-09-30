package config

import (
	"strings"

	cmap "github.com/orcaman/concurrent-map/v2"
)

type Trie[T any] struct {
	children *cmap.ConcurrentMap[string, *Trie[T]]
	value    *T
}

func NewTrie[T any]() *Trie[T] {
	m := cmap.New[*Trie[T]]()
	return &Trie[T]{
		children: &m,
	}
}

// Set stores a value for the given domain in the trie.
func (t *Trie[T]) Set(domain string, value T) {
	parts := strings.Split(domain, ".")
	node := t

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		newMap := cmap.New[*Trie[T]]()
		newNode := &Trie[T]{
			children: &newMap,
		}

		node.children.SetIfAbsent(part, newNode)

		node, _ = node.children.Get(part)
	}

	node.value = &value
}

// Get finds a value for the given domain, supporting wildcard matching.
func (t *Trie[T]) Get(domain string) *T {
	parts := strings.Split(domain, ".")
	node := t

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		if exactNode, ok := node.children.Get(part); ok {
			node = exactNode
			continue
		}

		if wildcardNode, ok := node.children.Get("*"); ok {
			node = wildcardNode
			continue
		}

		return nil
	}

	return node.value
}

// Delete removes a value from the trie. Returns true if the value was found and deleted.
func (t *Trie[T]) Delete(domain string) bool {
	parts := strings.Split(domain, ".")

	path := make([]*Trie[T], 0, len(parts)+1)
	keys := make([]string, 0, len(parts))

	node := t
	path = append(path, node)

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		keys = append(keys, part)

		if nextNode, ok := node.children.Get(part); ok {
			node = nextNode
			path = append(path, node)
		} else {
			return false
		}
	}

	if node.value == nil {
		return false
	}

	node.value = nil

	for i := len(path) - 1; i > 0; i-- {
		currentNode := path[i]
		parentNode := path[i-1]
		key := keys[i-1]

		if currentNode.value == nil && currentNode.children.Count() == 0 {
			parentNode.children.Remove(key)
		} else {
			break
		}
	}

	return true
}

// DeleteValue removes only the value but keeps the node structure intact.
func (t *Trie[T]) DeleteValue(domain string) bool {
	parts := strings.Split(domain, ".")
	node := t

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if nextNode, ok := node.children.Get(part); ok {
			node = nextNode
		} else {
			return false
		}
	}

	if node.value == nil {
		return false
	}

	node.value = nil
	return true
}

// GetKeysWithVal return all keys with non-nil value.
func (t *Trie[T]) GetKeysWithVal() []string {
	var result []string
	t.collectKeys(&result, []string{})
	return result
}

// collectKeys is a helper function that recursively traverses the trie.
func (t *Trie[T]) collectKeys(result *[]string, path []string) {
	if t.value != nil {
		domain := make([]string, len(path))
		for i := range path {
			domain[i] = path[len(path)-1-i]
		}
		*result = append(*result, strings.Join(domain, "."))
	}

	t.children.IterCb(func(key string, child *Trie[T]) {
		newPath := append(path, key)
		child.collectKeys(result, newPath)
	})
}
