package controllers

import (
	"errors"
	"html/template"
	"net/http"

	"github.com/LutfiEkaprima/Goproject/config"
	"github.com/LutfiEkaprima/Goproject/entities"
	"github.com/LutfiEkaprima/Goproject/models"
	"github.com/LutfiEkaprima/Goproject/libraries"

	"golang.org/x/crypto/bcrypt"

	"os"
	"path/filepath"
)

type UserInput struct {
	Username string `validate:"required"`
	Password string `validate:"required"`
}

var userModel = models.NewUserModel()
var validation = libraries.NewValidation()

func Index(w http.ResponseWriter, r *http.Request) {

	session, _ := config.Store.Get(r, config.SESSION_ID)

	if len(session.Values) == 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	} else {

		if session.Values["loggedIn"] != true {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		} else {

			data := map[string]interface{}{
				"nama_lengkap": session.Values["nama_lengkap"],
			}

			temp, _ := template.ParseFiles("views/index.html")
			temp.Execute(w, data)
		}

	}
}

func Login(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {
		temp, _ := template.ParseFiles("views/login.html")
		temp.Execute(w, nil)
	} else if r.Method == http.MethodPost {
		// proses login
		r.ParseForm()
		UserInput := &UserInput{
			Username: r.Form.Get("username"),
			Password: r.Form.Get("password"),
		}

		errorMessages := validation.Struct(UserInput)

		if errorMessages != nil {

			data := map[string]interface{}{
				"validation": errorMessages,
			}

			temp, _ := template.ParseFiles("views/login.html")
			temp.Execute(w, data)

		} else {

			var user entities.User
			userModel.Where(&user, "username", UserInput.Username)

			var message error
			if user.Username == "" {
				message = errors.New("Username yang anda input salah!")
			} else {
				// pengecekan password
				errPassword := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(UserInput.Password))
				if errPassword != nil {
					message = errors.New("Password yang anda input salah!")
				}
			}

			if message != nil {

				data := map[string]interface{}{
					"error": message,
				}

				temp, _ := template.ParseFiles("views/login.html")
				temp.Execute(w, data)
			} else {
				// set session
				session, _ := config.Store.Get(r, config.SESSION_ID)

				session.Values["loggedIn"] = true
				session.Values["email"] = user.Email
				session.Values["username"] = user.Username
				session.Values["nama_lengkap"] = user.NamaLengkap

				session.Save(r, w)

				http.Redirect(w, r, "/", http.StatusSeeOther)
			}
		}

	}

}

func Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := config.Store.Get(r, config.SESSION_ID)
	// delete session
	session.Options.MaxAge = -1
	session.Save(r, w)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func Register(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodGet {

		temp, _ := template.ParseFiles("views/register.html")
		temp.Execute(w, nil)

	} else if r.Method == http.MethodPost {
		// melakukan proses registrasi

		// mengambil inputan form
		r.ParseForm()

		user := entities.User{
			NamaLengkap: r.Form.Get("nama_lengkap"),
			Email:       r.Form.Get("email"),
			Username:    r.Form.Get("username"),
			Password:    r.Form.Get("password"),
			Cpassword:   r.Form.Get("cpassword"),
		}

		errorMessages := validation.Struct(user)

		if errorMessages != nil {

			data := map[string]interface{}{
				"validation": errorMessages,
				"user":       user,
			}

			temp, _ := template.ParseFiles("views/register.html")
			temp.Execute(w, data)
		} else {

			// hashPassword
			hashPassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
			user.Password = string(hashPassword)

			// insert ke database
			userModel.Create(user)

			data := map[string]interface{}{
				"pesan": "Registrasi berhasil",
			}
			temp, _ := template.ParseFiles("views/register.html")
			temp.Execute(w, data)
		}
	}

}
func DownloadUAS(w http.ResponseWriter, r *http.Request) {
		// Path ke file yang akan diunduh
		filePath := "./views/Jadwal_UAS_Reguler_PSIF_ITI.xlsx"

		// Buka file
		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		// Dapatkan informasi file
		fileInfo, err := file.Stat()
		if err != nil {
			http.Error(w, "Unable to get file information", http.StatusInternalServerError)
			return
		}

		// Set header untuk memicu unduhan
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath))
		w.Header().Set("Content-Type", "application/octet-stream")
		//w.Header().Set("Content-Length", fileInfo.Size())

		// Salin isi file ke response writer
		http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), file)
}

func DownloadUTS(w http.ResponseWriter, r *http.Request) {
		// Path ke file yang akan diunduh
		filePath := "./views/Jadwal_UTS_Reguler_PSIF_ITI.xlsx"

		// Buka file
		file, err := os.Open(filePath)
		if err != nil {
			http.Error(w, "File not found", http.StatusNotFound)
			return
		}
		defer file.Close()

		// Dapatkan informasi file
		fileInfo, err := file.Stat()
		if err != nil {
			http.Error(w, "Unable to get file information", http.StatusInternalServerError)
			return
		}

		// Set header untuk memicu unduhan
		w.Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(filePath))
		w.Header().Set("Content-Type", "application/octet-stream")
		//w.Header().Set("Content-Length", fileInfo.Size())

		// Salin isi file ke response writer
		http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), file)
	

}
