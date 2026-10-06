package sbom

import "fmt"

// Loss describes a semantic item dropped or degraded during conversion.
type Loss struct {
	Field   string
	Subject string
	Detail  string
}

// Convert rewrites a document to the target spec version and reports every
// semantic loss incurred. V1 -> V2 is lossless (V2 is a superset).
// V2 -> V1 drops the Supplier field, which V1 cannot represent; each
// dropped supplier is reported as a Loss.
func Convert(doc *Document, target SpecVersion) (*Document, []Loss, error) {
	if doc == nil {
		return nil, nil, fmt.Errorf("nil document")
	}
	switch target {
	case SpecV1, SpecV2:
	default:
		return nil, nil, fmt.Errorf("unsupported target spec %q", target)
	}
	out := &Document{
		Spec:         target,
		Components:   make([]Component, len(doc.Components)),
		Dependencies: map[string][]string{},
	}
	var losses []Loss
	for i, c := range doc.Components {
		nc := c
		if c.Hashes != nil {
			nc.Hashes = map[string]string{}
			for k, v := range c.Hashes {
				nc.Hashes[k] = v
			}
		}
		nc.Licenses = append([]string(nil), c.Licenses...)
		if target == SpecV1 && c.Supplier != "" {
			losses = append(losses, Loss{
				Field:   "supplier",
				Subject: c.Name + "@" + c.Version,
				Detail:  fmt.Sprintf("supplier %q not representable in spec %s", c.Supplier, SpecV1),
			})
			nc.Supplier = ""
		}
		out.Components[i] = nc
	}
	for from, tos := range doc.Dependencies {
		out.Dependencies[from] = append([]string(nil), tos...)
	}
	return out, losses, nil
}
