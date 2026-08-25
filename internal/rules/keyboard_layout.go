package rules

type keyboardLayout struct {
	name string
	rows [][]rune
}

var qwertyLayout = keyboardLayout{
	name: "qwerty",
	rows: [][]rune{
		[]rune("qwertyuiop"),
		[]rune("asdfghjkl"),
		[]rune("zxcvbnm"),
	},
}

var jcukenLayout = keyboardLayout{
	name: "jcuken",
	rows: [][]rune{
		[]rune("йцукенгшщзхъ"),
		[]rune("фывапролджэ"),
		[]rune("ячсмитьбю"),
	},
}

func getKeyboardLayout(name string) (keyboardLayout, bool) {
	switch name {
	case "qwerty":
		return qwertyLayout, true
	case "jcuken":
		return jcukenLayout, true
	default:
		return keyboardLayout{}, false
	}
}
