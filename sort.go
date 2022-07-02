package merkletree

import (
	"bytes"
)

func (s Leaves) Len() int {

	return len(s)
}

func (s Leaves) Less(i, j int) bool {
	return bytes.Compare(s[i], s[j]) < 0
}

func (s Leaves) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
