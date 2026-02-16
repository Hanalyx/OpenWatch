//go:build !container

package cmd

func init() {
	// Override description for native builds
	rootCmd.Short = "OpenWatch Admin - Native installation management"
	rootCmd.Long = bold("OpenWatch Admin (owadm)") + ` - Administrative CLI for OpenWatch native installations.

Manages OpenWatch SCAP compliance scanning platform installed directly on the host.
For service lifecycle, use standard systemd commands (systemctl, journalctl).

Service Management (use systemctl):
  systemctl start openwatch.target     Start all OpenWatch services
  systemctl stop openwatch.target      Stop all OpenWatch services
  systemctl status openwatch-api       Check API service status
  journalctl -u openwatch-api -f       Follow API logs`

	// Hide container-specific flags in native builds
	rootCmd.PersistentFlags().MarkHidden("runtime")
}
