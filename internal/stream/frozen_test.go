package stream

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	"getvesta.sh/internal/stream/frozenpb"
)

// The frozen contract, pinned.
//
// ARCHITECTURE §23.2 says these messages may only ever change additively, because they
// are how a stranded agent is recovered: an agent too old to parse the current Spec must
// still be able to say hello and be handed a new binary. A comment saying so decays. This
// does not — removing a field, renumbering one, or changing a type fails here.
//
// Adding a field is allowed and expected; a new entry appended to one of these maps is a
// legitimate change. Changing or deleting an existing entry is not, and a reviewer seeing
// such a diff should refuse it.
var frozenContract = map[string]map[int32]string{
	"vesta.frozen.v1.Hello": {
		1: "node_id:string",
		2: "version:string",
		3: "protocol:uint32",
		4: "agent_pubkey:bytes",
		5: "applied_revision:string",
		6: "arch:string",
	},
	"vesta.frozen.v1.HelloAck": {
		1: "accepted:bool",
		2: "server_protocol:uint32",
		3: "min_supported_protocol:uint32",
		4: "message:string",
		5: "update_offered:bool",
	},
	"vesta.frozen.v1.UpdateOffer": {
		1: "version:string",
		2: "sha256:string",
		3: "signature:bytes",
		4: "size:uint64",
		5: "required:bool",
		6: "arch:string",
	},
	"vesta.frozen.v1.UpdateChunk": {
		1: "data:bytes",
		2: "offset:uint64",
	},
	"vesta.frozen.v1.UpdateResult": {
		1: "ok:bool",
		2: "version:string",
		3: "error:string",
		4: "reverted:bool",
	},
}

func TestFrozenContractIsUnchanged(t *testing.T) {
	messages := []protoreflect.ProtoMessage{
		(*frozenpb.Hello)(nil),
		(*frozenpb.HelloAck)(nil),
		(*frozenpb.UpdateOffer)(nil),
		(*frozenpb.UpdateChunk)(nil),
		(*frozenpb.UpdateResult)(nil),
	}

	seen := map[string]bool{}
	for _, m := range messages {
		desc := m.ProtoReflect().Descriptor()
		name := string(desc.FullName())
		seen[name] = true

		want, ok := frozenContract[name]
		if !ok {
			t.Errorf("%s is in the frozen package but not pinned by this test", name)
			continue
		}

		got := map[int32]string{}
		fields := desc.Fields()
		for i := 0; i < fields.Len(); i++ {
			f := fields.Get(i)
			got[int32(f.Number())] = fmt.Sprintf("%s:%s", f.Name(), f.Kind())
		}

		for num, sig := range want {
			actual, present := got[num]
			if !present {
				t.Errorf("%s: field %d (%s) was REMOVED — this breaks fleet recovery for every agent that still sends it",
					name, num, sig)
				continue
			}
			if actual != sig {
				t.Errorf("%s: field %d changed from %q to %q — renumbering or retyping a frozen field breaks fleet recovery",
					name, num, sig, actual)
			}
		}
		for num, sig := range got {
			if _, pinned := want[num]; !pinned {
				t.Logf("%s: field %d (%s) is new — additive changes are allowed; pin it in frozenContract",
					name, num, sig)
			}
		}
	}

	var missing []string
	for name := range frozenContract {
		if !seen[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("pinned message(s) no longer exist: %s", strings.Join(missing, ", "))
	}
}

// The frozen messages must stay in their own package. If they ever import from the
// evolving contract, a change over there could break recovery over here — which is the
// coupling the split exists to prevent.
func TestFrozenPackageHasNoEvolvingDependencies(t *testing.T) {
	file := (*frozenpb.Hello)(nil).ProtoReflect().Descriptor().ParentFile()
	imports := file.Imports()
	for i := 0; i < imports.Len(); i++ {
		path := imports.Get(i).Path()
		if strings.Contains(path, "node.proto") {
			t.Errorf("frozen.proto imports %s: the frozen contract must not depend on the evolving one", path)
		}
	}
}
