package merkletree

import "regexp"

func IsHexString(v string) (bool, error) {

	return regexp.MatchString("/^(0x)?[0-9A-Fa-f]*$/", v)
}
