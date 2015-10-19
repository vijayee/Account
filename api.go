package account

import (
	"github.com/emicklei/go-restful"
	"net/http"
)

type logOnRequest struct {
	Username string
	Password string
}
type logOnResponse struct {
	Token []byte
}
type registrationRequest struct {
	Username  string
	Password  string
	Question1 string
	Question2 string
	Question3 string
	Answer1   string
	Answer2   string
	Answer3   string
}

type registrationResponse struct {
	Device []byte
}

type changePasswordRequest struct {
	Username    string
	Password    string
	NewPassword string
}
type changePasswordResponse struct {
	Device []byte
}
type changeQuestionsRequest struct {
	Username  string
	Password  string
	Question1 string
	Question2 string
	Question3 string
	Answer1   string
	Answer2   string
	Answer3   string
}
type recoverRequest struct {
	Username    string
	NewPassword string
	Answer1     string
	Answer2     string
	Answer3     string
}

type recoverResponse struct {
	Device []byte
}

type deviceLoginRequest struct {
	Device []byte
}

func NewAPI() *restful.WebService {
	accountAPI := new(restful.WebService)
	accountAPI.Path("/account")
	accountAPI.Consumes(restful.MIME_JSON)
	accountAPI.Produces(restful.MIME_JSON)
	accountAPI.Route(accountAPI.PUT("").To(createAccount))
	accountAPI.Route(accountAPI.POST("").To(loginAccount))
	accountAPI.Route(accountAPI.POST("/device").To(deviceLogin))
	accountAPI.Route(accountAPI.POST("/recover").To(recoverAccount))
	accountAPI.Route(accountAPI.PATCH("/questions").To(changeQuestions))
	accountAPI.Route(accountAPI.PATCH("").To(changePassword))
	return accountAPI
}

func createAccount(request *restful.Request, response *restful.Response) {
	registration := new(registrationRequest)
	err := request.ReadEntity(&registration)

	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	} else {
		registrationRes := new(registrationResponse)
		registrationRes.Device, err = Register(registration.Username, registration.Password, registration.Question1,
			registration.Question2, registration.Question3, registration.Answer1,
			registration.Answer2, registration.Answer3)
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
		_, err = LogOn(login.Username, login.Password)
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
	} else {
		changeRes := new(changePasswordResponse)
		changeRes.Device, err = ChangePassword(change.Username, change.Password, change.NewPassword)
		if err != nil {
			response.WriteError(http.StatusInternalServerError, err)
		} else {
			response.WriteEntity(changeRes)
		}
	}
}

func changeQuestions(request *restful.Request, response *restful.Response) {
	change := new(changeQuestionsRequest)
	err := request.ReadEntity(&change)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	} else {

		err = ChangeQuestions(change.Username, change.Password, change.Question1,
			change.Question2, change.Question3, change.Answer1,
			change.Answer2, change.Answer3)
		if err != nil {
			response.WriteError(http.StatusInternalServerError, err)
		}

	}
}

func recoverAccount(request *restful.Request, response *restful.Response) {
	recovery := new(recoverRequest)
	err := request.ReadEntity(&recovery)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	recoverRes := new(recoverResponse)
	recoverRes.Device, err = Recover(recovery.Username, recovery.NewPassword, recovery.Answer1,
		recovery.Answer2, recovery.Answer3)
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
	} else {
		_, err = DeviceLogOn(login.Device)
		if err != nil {
			response.WriteError(http.StatusInternalServerError, err)
		} else {
			loginRes := new(logOnResponse)
			loginRes.Token = []byte("Let em in, Frank")
			response.WriteEntity(loginRes)
		}
	}

}
