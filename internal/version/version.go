package version

// Build information variables that are set at compile time via ldflags
var (
	Version = "snapshot"
	Commit  = "unknown"
	Date    = "unknown"
	BinName = "AWS OIDC Warden"
)

// Info holds build information
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	BinName string `json:"binName"`
}

// Get returns the current build information
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		Date:    Date,
		BinName: BinName,
	}
}
