package util

// Returns elements of needle not present in haystack
func Missing(haystack, needle []string) []string {
	var notFound []string

outer:
	for _, n := range needle {
		for _, h := range haystack {
			if n == h {
				continue outer
			}
		}
		notFound = append(notFound, n)
	}

	return notFound
}
