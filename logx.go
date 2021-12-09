package wappalyzer

import "fmt"

func (w *Wappalyzer) PrintError(a ...interface{}) {
	if w.displayError {
		fmt.Println(a...)
	}
}
