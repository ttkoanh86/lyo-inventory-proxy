package main

import (
	"context"
	"fmt"

	"github.com/valkey-io/valkey-go"
)

var ctx context.Context
var vk valkey.Client

func main() {

	vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{"localhost:6379"},
	})

	if err != nil {
		panic(err)
	}

	ctx = context.Background()

	vkrs := vk.Do(ctx, vk.B().Get().Key("UD8ASkuhVTZxUykjcUipA5").Build())

	vkrs_bin, err := vkrs.ToString()
	fmt.Println(vkrs_bin == "")

}
