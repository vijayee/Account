package account

import (
	"github.com/emicklei/go-restful"
	//"strings"
	"fmt"
	"net/http"
)

type logOnRequest struct {
	username string
	password string
}
type logOnResponse struct {
	Token []byte
}
type registrationRequst struct {
	username  string
	password  string
	question1 string
	question2 string
	question3 string
	answer1   string
	answer2   string
	answer3   string
}

type registrationResponse struct {
	Device []byte
}

type changePasswordRequest struct {
	username    string
	password    string
	newPassword string
}
type changePasswordResponse struct {
	Device []byte
}
type changeQuestionsRequest struct {
	username  string
	password  string
	question1 string
	question2 string
	question3 string
	answer1   string
	answer2   string
	answer3   string
}
type recoverRequest struct {
	username    string
	newPassword string
	answer1     string
	answer2     string
	answer3     string
}

type recoverResponse struct {
	Device []byte
}
type deviceLoginRequest struct {
	device []byte
}

func NewAPI() *restful.WebService {
	accountAPI := new(restful.WebService)
	accountAPI.Path("/account")
	accountAPI.Consumes(restful.MIME_JSON)
	accountAPI.Produces(restful.MIME_JSON)
	accountAPI.Route(accountAPI.PUT("").To(createAccount))
	accountAPI.Route(accountAPI.POST("").To(loginAccount))
	accountAPI.Route(accountAPI.GET("/device").To(deviceLogin))
	accountAPI.Route(accountAPI.POST("/recover").To(recoverAccount))
	accountAPI.Route(accountAPI.PATCH("/questions").To(changeQuestions))
	accountAPI.Route(accountAPI.PATCH("").To(changePassword))
	return accountAPI
}

func createAccount(request *restful.Request, response *restful.Response) {
	registration := new(registrationRequst)
	err := request.ReadEntity(&registration)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	} else {
		fmt.Printf("Username: %s\n", registration.username)
		registrationRes := new(registrationResponse)
		registrationRes.Device, err = Register(registration.username, registration.password, registration.question1,
			registration.question2, registration.question3, registration.answer1,
			registration.answer2, registration.answer3)
		if err != nil {
			response.WriteError(http.StatusInternalServerError, err)
		} else {
			response.WriteEntity(registrationRes)
		}
	}

}

func loginAccount(request *restful.Request, response *restful.Response) {
	login := new(logOnRequest)
	err := request.ReadEntity(&login)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	} else {
		_, err = LogOn(login.username, login.password)
		if err != nil {
			response.WriteError(http.StatusInternalServerError, err)
		} else {
			loginRes := new(logOnResponse)
			loginRes.Token = []byte("Let em in, Frank")
			response.WriteEntity(loginRes)
		}
	}

}

func changePassword(request *restful.Request, response *restful.Response) {
	change := new(changePasswordRequest)
	err := request.ReadEntity(&change)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	changeRes := new(changePasswordResponse)
	changeRes.Device, err = ChangePassword(change.username, change.password, change.newPassword)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}

	response.WriteEntity(changeRes)
}

func changeQuestions(request *restful.Request, response *restful.Response) {
	change := new(changeQuestionsRequest)
	err := request.ReadEntity(&change)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	err = ChangeQuestions(change.username, change.password, change.question1,
		change.question2, change.question3, change.answer1,
		change.answer2, change.answer3)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
}

func recoverAccount(request *restful.Request, response *restful.Response) {
	recovery := new(recoverRequest)
	err := request.ReadEntity(&recovery)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	recoverRes := new(recoverResponse)
	recoverRes.Device, err = Recover(recovery.username, recovery.newPassword, recovery.answer1,
		recovery.answer2, recovery.answer3)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	response.WriteEntity(recoverRes)
}

func deviceLogin(request *restful.Request, response *restful.Response) {
	login := new(deviceLoginRequest)
	err := request.ReadEntity(&login)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	_, err = DeviceLogOn(login.device)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	loginRes := new(logOnResponse)
	loginRes.Token = []byte("Let em in, Frank")
	response.WriteEntity(loginRes)

}
