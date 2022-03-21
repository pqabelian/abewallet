package prompt

import (
	"crypto/rand"
	"fmt"
	"github.com/abesuite/abewallet/wordlists"
	"reflect"
	"testing"
)

func Test_seedToWords(t *testing.T) {
	seed:=make([]byte,64)
	n,err:=rand.Read(seed)
	if err!=nil || n!=64{
		t.Errorf("no enough random integer %v",len(seed))
	}
	tests := []struct {
		name     string
		seed     []byte
		wordlist []string
		wordMap  map[string]int
		want     []string
	}{
		// TODO: Add test cases.
		{
			name: "1",
			seed: seed,
			wordlist: wordlists.English,
			wordMap: wordlists.EnglishMap,
			want:nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := seedToWords(tt.seed, tt.wordlist)
			res:=wordsToSeed(got,tt.wordMap)
			if !reflect.DeepEqual(res[:len(tt.seed)],tt.seed) {
				fmt.Println(seed)
				fmt.Println(got)
				fmt.Println(res)
				for i := 0; i < len(seed); i++ {
					if res[i]!=tt.seed[i]{
						fmt.Println("error index = ",i)
					}
				}
				t.Errorf("error")
			}
		})
	}
}
