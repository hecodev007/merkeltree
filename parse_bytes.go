package merkletree

func paddingZero(data ...interface{}) []byte {
	var v [][]byte
	for _, item := range data {
		b := parseBytes(item, -1)
		v = append(v, b)
	}

	return concatByteSlices(v...)
}
