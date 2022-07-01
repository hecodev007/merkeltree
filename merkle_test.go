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
	/*isHex, err := IsHexString(t.x)

	fmt.Println(t.x, isHex, err)

	//if isHex {
	t.x = strings.Replace(t.x, "0x", "", 1)
	//}
	*/

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
	list = append(list, TestContent{x: "0x0000007adc3815c056c91dbc5ec48c4fd0950b49"})
	list = append(list, TestContent{x: "0x00010a9bbde3f6ec395c179e36f1df24e59bd824"})
	list = append(list, TestContent{x: "0x0004932ff86fbdb0e7cf99203111624ea57cd772"})
	list = append(list, TestContent{x: "0x01291849cc904161603c1c60ff86658ad7eadb8d"})
	list = append(list, TestContent{x: "0x0582f324704bf44f7e9e80a2ca68f08e91e45927"})
	/*	list = append(list, TestContent{x: "e"})
		list = append(list, TestContent{x: "f"})
		list = append(list, TestContent{x: "g"})
		list = append(list, TestContent{x: "h"})
		list = append(list, TestContent{x: "i"})
		list = append(list, TestContent{x: "j"})
		list = append(list, TestContent{x: "k"})*/

	tr := New(list)
	_ = tr

	//tr.AddLeaf(TestContent{x: "e"})
	root := tr.GetRoot()
	leaf := TestContent{x: "0x0582f324704bf44f7e9e80a2ca68f08e91e45927"}

	l, _ := leaf.CalculateHash()

	proof := tr.GetProof(l)
	fmt.Println(tr.GetHexLayers())

	t.Fatal(tr.Verify(proof, l, root)) // true

	//t.Fatal(tr.GetHexLeaves())
	//t.Fatal(tr.GetHexLayers())
}
