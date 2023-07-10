package wf

import (
	"golang.org/x/sys/windows"
)

type RuleEnumerator struct {
	session      *Session
	enumTemplate fwpmFilterEnumTemplate0
}

func (e RuleEnumerator) WithProvider(provider ProviderID) RuleEnumerator {
	e.enumTemplate.ProviderKey = &provider
	return e
}

func (e RuleEnumerator) WithLayer(layer LayerID) RuleEnumerator {
	e.enumTemplate.LayerKey = layer
	return e
}

func (e RuleEnumerator) WithType(typ FilterEnumType) RuleEnumerator {
	e.enumTemplate.EnumType = typ
	return e
}

func (e RuleEnumerator) WithFlags(flags FilterEnumFlags) RuleEnumerator {
	e.enumTemplate.Flags = flags
	return e
}

func (e RuleEnumerator) WithProviderContext(provider ProviderID, contextType uint32) RuleEnumerator {
	contextEnumTemplate := fwpmProviderContextEnumTemplate0{
		ProviderKey:         new(ProviderID),
		ProviderContextType: contextType,
	}
	*contextEnumTemplate.ProviderKey = provider
	e.enumTemplate.ProviderContextTemplate = &contextEnumTemplate
	return e
}

func (e RuleEnumerator) WithActionMask(mask ActionFlag) RuleEnumerator {
	e.enumTemplate.ActionMask = mask
	return e
}

func (e RuleEnumerator) WithCalloutKey(key CalloutID) RuleEnumerator {
	e.enumTemplate.CalloutKey = &key
	return e
}

func (e RuleEnumerator) Execute() ([]*Rule, error) {
	var enum windows.Handle
	if err := fwpmFilterCreateEnumHandle0(e.session.handle, &e.enumTemplate, &enum); err != nil {
		return nil, err
	}
	defer fwpmFilterDestroyEnumHandle0(e.session.handle, enum)

	var ret []*Rule

	for {
		rules, err := e.session.getRulePage(enum)
		if err != nil {
			return nil, err
		}

		if len(rules) == 0 {
			return ret, nil
		}

		ret = append(ret, rules...)
	}
}

func (s *Session) EnumerateRules(typ FilterEnumType, layer LayerID) RuleEnumerator {
	return RuleEnumerator{
		session: s,
		enumTemplate: fwpmFilterEnumTemplate0{
			EnumType: typ,
			LayerKey: layer,
		},
	}
}
