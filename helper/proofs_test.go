package helper

import (
	"fmt"
	"github.com/authur117/merkletree"
	"testing"
)

type Leaf struct {
	Data    string `json:"data"`
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
	Index   int64  `json:"index"`
}

func formatNumber(num int64, padLen int) string {
	return fmt.Sprintf("%0*s", padLen, fmt.Sprintf("0x%x", num)[2:])
}

func (n *Leaf) MakeLeafData() string {

	return fmt.Sprintf("%s%s%s", n.Address, formatNumber(n.Amount, 64), formatNumber(n.Index, 64))
}

func TestFormatNumber(t *testing.T) {

	//t.Fatal(fmt.Sprintf("%0*s", 64, fmt.Sprintf("0x%x", 222)[2:]))
	var leaves = []Leaf{
		{
			Address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
			Amount:  0,
			Index:   0,
		}, {
			Address: "0x07cB5cD417d8EB9373849e8F482Cb2031d9F1e43",
			Amount:  1,
			Index:   1,
		}, {
			Address: "0xE8e3a028903e5435bB2CD7DA30119d37eEf66999",
			Amount:  2,
			Index:   2,
		},
	}

	tr := merkletree.New(merkletree.SHA3)
	tr.WithOption(merkletree.Option{
		Sort: true,
	})

	var leavesSlice []merkletree.Content
	for k, v := range leaves {
		leaves[k].Data = v.MakeLeafData()
		leavesSlice = append(leavesSlice, merkletree.Content{
			X: leaves[k].Data,
		})
	}

	tr.InitLeaves(leavesSlice)

	//tr.AddLeaf(Content{x: "e"})
	root := tr.GetRoot()

	leaf := merkletree.Content{X: leaves[1].MakeLeafData()}

	tr.GetHexLeaves()
	//root, _ = hex.DecodeString("5651b0b746e49be1307faa82cdef9a6cbd454d9b0df2318cd795e8adb877c594")

	proof := tr.GetProof(leaf)
	fmt.Println("proof:",tr.String())

	b,err:=tr.Verify(proof, leaf, root)
	fmt.Println(b,err)
}
