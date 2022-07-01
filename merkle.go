package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"math"
	"sort"
)

type Option struct {
	Sort       bool
	SortLeaves bool
	SortPairs  bool
}

type Content interface {
	CalculateHash() ([]byte, error)
	Equals(other Content) (bool, error)
}

type Leaves [][]byte

type Proof struct {
	Position string
	Data     []byte
}

type MerkleTree struct {
	sort          bool
	sortPairs     bool
	sortLeaves    bool
	IsBitcoinTree bool
	Layers        []Leaves
	Leaves        Leaves
	hashFn        func() hash.Hash
}

func New(leaves []Content) *MerkleTree {
	t := &MerkleTree{
		hashFn: sha256.New,
	}

	t.Leaves = make(Leaves, 0)
	for _, l := range leaves {
		hashByte, _ := l.CalculateHash()
		t.Leaves = append(t.Leaves, hashByte)
	}
	t.createLayers()
	return t

}

func (t *MerkleTree) WithOption(option Option) {
	if option.Sort {
		t.sort = option.Sort
		t.sortPairs = true
		t.sortLeaves = true
	}

	if option.SortPairs {
		t.sortPairs = option.SortPairs
	}
	if option.SortLeaves {
		t.sortLeaves = option.SortLeaves
	}
}

func (t *MerkleTree) createLayers() error {

	if t.sortLeaves {
		sort.Sort(t.Leaves)
	}

	t.Layers = make([]Leaves, 0)

	t.Layers = append(t.Layers, t.Leaves)

	err := t.createHashes(t.Leaves)

	return err
}

func (t *MerkleTree) createHashes(nodes Leaves) error {
	for {
		if len(nodes) == 1 {
			break
		}
		layerIndex := len(t.Layers)
		t.Layers = append(t.Layers, Leaves{})
		for i := 0; i < len(nodes); i = i + 2 {
			if i+1 == len(nodes) {
				if len(nodes)%2 == 1 {
					t.Layers[layerIndex] = append(t.Layers[layerIndex], nodes[i])
					continue
				}
			}

			left := nodes[i]
			right := nodes[i+1]
			if i+1 == len(nodes) {
				right = left
			}
			hashFn := t.hashFn()

			hashByte := append(left, right...)
			if _, err := hashFn.Write(hashByte); err != nil {
				return err
			}

			t.Layers[layerIndex] = append(t.Layers[layerIndex], hashFn.Sum(nil))

		}

		nodes = t.Layers[layerIndex]
	}

	return nil
}

func (t *MerkleTree) AddLeaf(leaf Content) {
	byteLeaf, _ := leaf.CalculateHash()

	t.Leaves = append(t.Leaves, byteLeaf)
	t.createLayers()
}

func (t *MerkleTree) AddLeaves(leaves []Content) {
	for _, l := range leaves {
		hashByte, _ := l.CalculateHash()
		t.Leaves = append(t.Leaves, hashByte)
	}
	t.createLayers()
}

func (t *MerkleTree) GetLeafCount() int {
	return len(t.Leaves)
}

func (t *MerkleTree) GetLeaf(index int) []byte {
	if index < 0 || index > len(t.Leaves)-1 {
		return []byte("")
	}
	return t.Leaves[index]
}

func (t *MerkleTree) GetHexLeaves() []string {
	var leaves []string
	for _, v := range t.Leaves {
		leaves = append(leaves, hex.EncodeToString(v))
	}

	return leaves
}

func (t *MerkleTree) GetLayers() []Leaves {

	return t.Layers
}

func (t *MerkleTree) GetLayerCount() int {

	return len(t.Layers)
}

func (t *MerkleTree) GetHexLayers() [][]string {
	var layers [][]string
	for _, v := range t.Layers {
		var layer []string
		for _, item := range v {
			layer = append(layer, hex.EncodeToString(item))
		}
		layers = append(layers, layer)
	}

	return layers
}

func (t *MerkleTree) GetRoot() []byte {
	l := len(t.Layers)
	if l == 0 {
		return []byte("")
	}
	return t.Layers[l-1][0]
}

func (t *MerkleTree) GetHexRoot() string {
	return hex.EncodeToString(t.GetRoot())
}

func (t *MerkleTree) GetProof(leaf []byte, index ...int) []*Proof {
	var idx int
	var proofs []*Proof
	if len(index) == 0 {
		idx = -1
		for i := 0; i < len(t.Leaves); i++ {
			if bytes.Equal(t.Leaves[i], leaf) {
				idx = i
			}
		}
	}
	if idx <= -1 {
		return proofs
	}

	for i := 0; i < len(t.Layers); i++ {
		layer := t.Layers[i]
		isRightNode := idx % 2
		pairIndex := 0

		if isRightNode != 0 {
			pairIndex = idx - 1
		} else {
			if t.IsBitcoinTree && idx == (len(layer)-1) && i < (len(t.Layers)-1) {
				pairIndex = idx
			} else {
				pairIndex = idx + 1
			}
		}

		if pairIndex < len(layer) {
			proof := &Proof{
				Data: layer[pairIndex],
			}
			if isRightNode != 0 {
				proof.Position = "left"
			} else {
				proof.Position = "right"
			}
			proofs = append(proofs, proof)
		}
		div := idx / 2
		idx = int(math.Floor(float64(div)))
	}
	return proofs
}

func (t *MerkleTree) Verify(proofs []*Proof, targetNode []byte, root []byte) (bool, error) {
	var verify bool
	for i := 0; i < len(proofs); i++ {
		var buffers [][]byte
		node := proofs[i]
		data := node.Data
		isLeftNode := node.Position == "left"
		buffers = append(buffers, targetNode)
		if isLeftNode {
			buffers = append([][]byte{data}, buffers...)
		} else {
			buffers = append(buffers, data)
		}

		h := t.hashFn()
		hashFn := append(buffers[0], buffers[1]...)
		if _, err := h.Write(hashFn); err != nil {
			return verify, err
		}
		targetNode = h.Sum(nil)
	}

	verify = bytes.Equal(targetNode, root)
	return verify, nil
}

func (t *MerkleTree) ResetTree() {
	t.Layers = []Leaves{}
	t.Leaves = Leaves{}
}

func (t *MerkleTree) String() string {
	s := ""
	for _, l := range t.Layers {
		for _, item := range l {
			s += hex.EncodeToString(item)
			s += "\n"
		}
	}
	return s
}
