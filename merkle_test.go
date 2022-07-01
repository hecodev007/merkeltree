package merkletree

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

type TestContent struct {
	x string
}

func (t TestContent) CalculateHash() ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write([]byte(t.x)); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

//Equals tests for equality of two Contents
func (t TestContent) Equals(other Content) (bool, error) {
	return t.x == other.(TestContent).x, nil
}

func TestMerkleTree_WithOptions(t *testing.T) {
	var list []Content
	list = append(list, TestContent{x: "a"})
	list = append(list, TestContent{x: "b"})
	list = append(list, TestContent{x: "c"})
	list = append(list, TestContent{x: "d"})
	/*	list = append(list, TestContent{x: "e"})
		list = append(list, TestContent{x: "f"})
		list = append(list, TestContent{x: "g"})
		list = append(list, TestContent{x: "h"})
		list = append(list, TestContent{x: "i"})
		list = append(list, TestContent{x: "j"})
		list = append(list, TestContent{x: "k"})*/

	tr := New(list)
	_ = tr

	tr.AddLeaf(TestContent{x: "e"})
	root := tr.GetRoot()
	leaf := TestContent{x: "e"}

	l, _ := leaf.CalculateHash()

	proof := tr.GetProof(l)
	fmt.Println(tr.GetHexLayers())

	t.Fatal(tr.Verify(proof, l, root)) // true

	//t.Fatal(tr.GetHexLeaves())
	//t.Fatal(tr.GetHexLayers())
}
