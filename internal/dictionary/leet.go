package dictionary

func normalizeLeetRune(r rune) rune {
	switch r {
	case '4':
		return 'a'
	case '3':
		return 'e'
	case '1':
		return 'l'
	case '0':
		return 'o'
	case '5', '$':
		return 's'
	case '@':
		return 'a'
	case '7':
		return 't'
	default:
		return r
	}
}
