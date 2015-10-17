package account

import (
	"github.com/emicklei/go-restful"
	//"strings"
	"net/http"
)

type logOnRequest struct {
	uname string
	pword string
}
type logOnResponse struct {
	uname string
	pword string
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
	device []byte
}

func NewAPI() *restful.WebService {
	accountAPI := new(restful.WebService)
	accountAPI.Path("/account")
	accountAPI.Consumes(restful.MIME_JSON)
	accountAPI.Produces(restful.MIME_JSON)
	accountAPI.Route(accountAPI.PUT("").To(createAccount))
	return accountAPI
}

func createAccount(request *restful.Request, response *restful.Response) {
	registration := new(registrationRequst)
	err := request.ReadEntity(&registration)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	registrationRes := new(registrationResponse)
	registrationRes.device, err = Register(registration.username, registration.password, registration.question1,
		registration.question2, registration.question3, registration.answer1,
		registration.answer2, registration.answer3)
	if err != nil {
		response.WriteError(http.StatusInternalServerError, err)
	}
	response.WriteEntity(registrationRes.device)

}
func loginAccount(request *restful.Request, response *restful.Response) {}
