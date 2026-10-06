package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
)

// canonicalDoc is the serialization schema. All slices are sorted before
// marshaling and all maps are emitted with sorted keys (encoding/json
// sorts map keys), so the output bytes depend only on the document
// content — never on traversal order, goroutine scheduling or runtime
// randomness.
type canonicalDoc struct {
	Spec         string             `json:"spec"`
	Serial       string             `json:"serial"`
	Components   []canonicalComp    `json:"components"`
	Dependencies map[string][]string `json:"dependencies"`
}

type canonicalComp struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	PURL     string            `json:"purl"`
	Hashes   map[string]string `json:"hashes,omitempty"`
	Licenses []string          `json:"licenses,omitempty"`
	Supplier string            `json:"supplier,omitempty"`
}

// Marshal serializes the document deterministically: identical inputs and
// config always produce byte-identical output regardless of map iteration
// order, goroutine scheduling or runtime randomness.
func Marshal(doc *Document) ([]byte, error) {
	cd := canonicalDoc{
		Spec:         string(doc.Spec),
		Serial:       "urn:sbomprov:doc:" + contentID(doc),
		Dependencies: map[string][]string{},
	}
	for _, c := range doc.Components {
		cc := canonicalComp{
			Name:    c.Name,
			Version: c.Version,
			PURL:    c.PURL,
			Hashes:  c.Hashes,
		}
		if len(c.Licenses) > 0 {
			lic := append([]string(nil), c.Licenses...)
			sort.Strings(lic)
			cc.Licenses = lic
		}
		if doc.Spec == SpecV2 {
			cc.Supplier = c.Supplier
		}
		cd.Components = append(cd.Components, cc)
	}
	// Defensive re-sort: canonical order is (name, version).
	sort.Slice(cd.Components, func(i, j int) bool {
		a, b := cd.Components[i], cd.Components[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	for from, tos := range doc.Dependencies {
		sorted := append([]string(nil), tos...)
		sort.Strings(sorted)
		cd.Dependencies[from] = sorted
	}
	// json.Marshal emits map keys in sorted order and struct fields in
	// declaration order: fully deterministic.
	return json.Marshal(cd)
}

// contentID is a stable content-derived identifier (no timestamps, no
// random UUIDs) so the serial number is reproducible too.
func contentID(doc *Document) string {
	h := sha256.New()
	h.Write([]byte(doc.Spec))
	for _, c := range doc.Components {
		h.Write([]byte(c.Name))
		h.Write([]byte{0})
		h.Write([]byte(c.Version))
		h.Write([]byte{0})
		h.Write([]byte(c.PURL))
		h.Write([]byte{0})
		if doc.Spec == SpecV2 {
			h.Write([]byte(c.Supplier))
		}
		h.Write([]byte{0})
		if len(c.Hashes) > 0 {
			keys := make([]string, 0, len(c.Hashes))
			for k := range c.Hashes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				h.Write([]byte(k))
				h.Write([]byte{0})
				h.Write([]byte(c.Hashes[k]))
				h.Write([]byte{0})
			}
		}
		lic := append([]string(nil), c.Licenses...)
		sort.Strings(lic)
		for _, l := range lic {
			h.Write([]byte(l))
			h.Write([]byte{0})
		}
	}
	for _, from := range sortedDepKeys(doc.Dependencies) {
		h.Write([]byte(from))
		h.Write([]byte{0})
		tos := append([]string(nil), doc.Dependencies[from]...)
		sort.Strings(tos)
		for _, to := range tos {
			h.Write([]byte(to))
			h.Write([]byte{0})
		}
	}
	sum := h.Sum(nil)
	const hexdigits = "0123456789abcdef"
	buf := make([]byte, 32) // first 16 bytes as hex is enough
	for i := 0; i < 16; i++ {
		buf[i*2] = hexdigits[sum[i]>>4]
		buf[i*2+1] = hexdigits[sum[i]&0xf]
	}
	return string(buf)
}

func sortedDepKeys(deps map[string][]string) []string {
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Digest returns the SHA-256 of the deterministic serialization.
func Digest(doc *Document) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	data, err := Marshal(doc)
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(data), nil
}
