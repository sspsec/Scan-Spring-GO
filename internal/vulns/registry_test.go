package vulns

import "testing"

// TestRegistryIntegrity 校验注册表的全局不变量：
// 信息完整、ID 唯一且有序、声明可利用的模块必须实现 Exploiter 且给出参数说明。
func TestRegistryIntegrity(t *testing.T) {
	all := All()
	if len(all) < 17 {
		t.Fatalf("expected at least 17 registered vulns, got %d", len(all))
	}

	seen := map[string]bool{}
	lastID := ""
	for _, v := range all {
		info := v.Info()
		if info.ID == "" || info.Name == "" {
			t.Fatalf("incomplete info: %+v", info)
		}
		if seen[info.ID] {
			t.Fatalf("duplicate vuln ID: %s", info.ID)
		}
		seen[info.ID] = true
		if info.ID < lastID {
			t.Fatalf("All() not sorted by ID: %s after %s", info.ID, lastID)
		}
		lastID = info.ID

		if info.HasExploit {
			if _, ok := v.(Exploiter); !ok {
				t.Fatalf("%s declares HasExploit but does not implement Exploiter", info.ID)
			}
			if info.ArgHint == "" {
				t.Fatalf("%s is exploitable but missing ArgHint", info.ID)
			}
		}
	}

	if _, ok := Get("CVE-2022-22963"); !ok {
		t.Fatal("Get failed for registered ID CVE-2022-22963")
	}
	if _, ok := Get("CVE-9999-0000"); ok {
		t.Fatal("Get returned an unregistered ID")
	}
}
