package main

import (
	"fmt"
	"net/http"

	authcontroller "github.com/LutfiEkaprima/Goproject/controllers"
)

func main() {
	http.HandleFunc("/downloadUAS",authcontroller.DownloadUAS)
	http.HandleFunc("/downloadUTS",authcontroller.DownloadUTS)
	http.HandleFunc("/", authcontroller.Index)
	http.HandleFunc("/login", authcontroller.Login)
	http.HandleFunc("/logout", authcontroller.Login)
	http.HandleFunc("/register", authcontroller.Register)

	fmt.Println("server started at localhost:9000")
	http.ListenAndServe(":9000", nil)

}