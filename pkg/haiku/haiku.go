package haiku

import (
    "math"
    "slices"
    "strings"
    "github.com/vishalkuo/bimap"
)

var biMap = bimap.NewBiMap[string, int]()

func init() {
    for i, word := range dictionary {
        biMap.Insert(word, i)
    }

    biMap.MakeImmutable()
}

//Base conv functions
func toDigits(n, b int) []int {
    capacity := int(math.Log(float64(n))/math.Log(float64(b))) + 1
    digits := make([]int, 0, capacity) // Pre-allocation
    for n > 0 {
        digits = append(digits, n%b)
        n /= b
    }

    slices.Reverse(digits)

    return digits
}


func fromDigits(digits []int, b int) int {
	n := 0
	for _, d := range digits {
		n = b*n + d
	}
	return n
}

func formatToDictionary(digits []int) (string) {
    resStr := ""

    for i, d := range digits {
        word, _ := biMap.GetInverse(d)
        if i == len(digits)-1 {
            resStr += word
        } else {
            resStr +=  word + "-"
        }
    }

    return resStr
}

func haikuToDigits(haiku string) ([]int) {
    words := strings.Split(haiku, "-")
    digits := make([]int, 0, len(words))

    for _, word := range words {
        d, _ := biMap.Get(word)
        digits = append(digits, d)
    }

    return digits
}

func ToHaiku(n int) (string) {
    return formatToDictionary(toDigits(n, len(dictionary)))
}

func FromHaiku(haiku string) (int) {
    return fromDigits(haikuToDigits(haiku), len(dictionary))
}

func FromHaikus(haiku []string) ([]int) {
    fgs := make([]int, 0, len(haiku))

    for _, h := range haiku {
        fgs = append(fgs, FromHaiku(h))
    }

    return fgs
}
