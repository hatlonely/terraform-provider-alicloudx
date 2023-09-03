package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/hatlonely/terraform-provider-alicloudx/internal/alicloudx"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: alicloudx.Provider,
	})
}
