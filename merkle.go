package merkletree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/sha3"
	"math"
	"sort"
)

const (
	SHA3 int = 1 + iota
	SHA256
)

type Option struct {
	Sort       bool
	SortLeaves bool
	SortPairs  bool
}

type Content struct {
	x string
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
	hashFn        int
}

func New(defaultHash int) *MerkleTree {
	t := &MerkleTree{
		hashFn: defaultHash,
	}
	t.Leaves = make(Leaves, 0)
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

func (t *MerkleTree) calculateHash(data interface{}) ([]byte, error) {

	switch t.hashFn {
	case SHA3:
		h := sha3.NewLegacyKeccak256()
		_, err := h.Write(paddingZero(data))
		if err != nil {
			return nil, err
		}
		return h.Sum(nil), nil
	case SHA256:
		switch v := data.(type) {
		case string:
			h := sha256.New()
			_, err := h.Write([]byte(v))
			if err != nil {
				return nil, err
			}
			return h.Sum(nil), nil
		case []byte:
			h := sha256.New()
			_, err := h.Write(v)
			if err != nil {
				return nil, err
			}
			return h.Sum(nil), nil
		}

	}

	return nil, nil

}

func (t *MerkleTree) InitLeaves(leaves []Content) {
	for _, l := range leaves {
		hashByte, _ := t.calculateHash(l.x)
		t.Leaves = append(t.Leaves, hashByte)
	}
	_ = t.createLayers()
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
			var hashByte []byte
			if t.sortPairs {
				tempLeaves := Leaves{left, right}
				sort.Sort(tempLeaves)
				hashByte = append(tempLeaves[0], tempLeaves[1]...)
			} else {
				hashByte = append(left, right...)
			}
			layerData, err := t.calculateHash(hashByte)
			if err != nil {
				return err
			}
			t.Layers[layerIndex] = append(t.Layers[layerIndex], layerData)

		}

		nodes = t.Layers[layerIndex]
	}

	return nil
}

func (t *MerkleTree) AddLeaf(leaf Content) {
	byteLeaf, _ := t.calculateHash(leaf.x)

	t.Leaves = append(t.Leaves, byteLeaf)
	t.createLayers()
}

func (t *MerkleTree) AddLeaves(leaves []Content) {
	for _, l := range leaves {
		hashByte, _ := t.calculateHash(l.x)
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

func (t *MerkleTree) GetProof(leafStr Content, index ...int) []*Proof {
	leaf, _ := t.calculateHash(leafStr.x)
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

func (t *MerkleTree) Verify(proofs []*Proof, targetNodeContent Content, root []byte) (bool, error) {
	targetNode, _ := t.calculateHash(targetNodeContent.x)
	var verify bool
	for i := 0; i < len(proofs); i++ {
		var buffers Leaves
		node := proofs[i]
		data := node.Data
		isLeftNode := node.Position == "left"

		if t.sortPairs {
			buffers = Leaves{data, targetNode}
			sort.Sort(buffers)
		} else {
			buffers = append(buffers, targetNode)
			if isLeftNode {
				buffers = append([][]byte{data}, buffers...)
			} else {
				buffers = append(buffers, data)
			}
		}

		var err error
		hashFn := append(buffers[0], buffers[1]...)
		targetNode, err = t.calculateHash(hashFn)
		_ = err
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
