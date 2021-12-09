package wappalyzer

type Categories map[string]Category

type Category struct {
	Groups   []int  `json:"groups"`
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}
