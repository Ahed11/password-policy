package dictionary

type trieNode struct {
	children map[rune]*trieNode
	terminal bool
}

type trie struct {
	root *trieNode
}

func newTrie() *trie {
	return &trie{
		root: &trieNode{
			children: make(map[rune]*trieNode),
		},
	}
}

func (t *trie) add(word string) {
	if t == nil || t.root == nil || word == "" {
		return
	}

	current := t.root

	for _, r := range word {
		next, exists := current.children[r]
		if !exists {
			next = &trieNode{
				children: make(map[rune]*trieNode),
			}
			current.children[r] = next
		}

		current = next
	}

	current.terminal = true
}

func buildTrie(words []string) *trie {
	result := newTrie()

	for _, word := range words {
		result.add(word)
	}

	return result
}
