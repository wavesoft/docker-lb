package utils

type HAPBackendRecord struct {
	Index int
	Port  int
	Host  string
	Order int

	// Needed for URL rewriting
	PathBe string
	PathFe string
}

type HAPMappingRecord struct {
	Index   int
	Path    string
	Backend *HAPBackendRecord
}

type HAPFrontendRecord struct {
	Index   int
	Domain  string
	SSL     bool
	Mapping []*HAPMappingRecord
}

// Sorting helpers
type byOrder []*HAPMappingRecord

func (s byOrder) Len() int {
	return len(s)
}
func (s byOrder) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s byOrder) Less(i, j int) bool {
	return s[i].Backend.Order < s[j].Backend.Order
}
