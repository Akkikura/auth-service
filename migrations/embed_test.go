package migrations

import "testing"

func TestMigrationVersion(t *testing.T) {
	cases := map[string]int64{
		"001_users.up.sql": 1,
		"42.up.sql":        42,
	}
	for name, want := range cases {
		got, err := migrationVersion(name)
		if err != nil {
			t.Fatalf("migrationVersion(%q): %v", name, err)
		}
		if got != want {
			t.Fatalf("migrationVersion(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestLoadMigrations(t *testing.T) {
	migrations, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if len(migrations) != 1 || migrations[0].version != 1 || migrations[0].name != "001_users.up.sql" {
		t.Fatalf("unexpected migrations: %#v", migrations)
	}
}
