package account

import (
	"github.com/emicklei/go-restful"
	"strings"
)

type logOnRequest struct {
	uname string
	pword string
}
type logOnResponse struct {
	uname string
	pword string
}

func NewAPI() *restful.WebService {
	accountAPI := new(restful.WebService)
	accountAPI.Path("/account")
	accountAPI.Consumes(restful.MIME_JSON)
	accountAPI.Produces(restful.MIME_JSON)
	accountAPI.Route(accountAPI.PUT("").To(createAccount))
	accountAPI.Route(accountAPI.PUT("").To(createAccount))
	accountAPI.Route(accountAPI.GET("/{username}").To(createAccount))
	return accountAPI
}
func createAccount(request *restful.Request, response *restful.Response) {
	host := request.HeaderParameter("Host")
	ips := strings.Split(ipheader, ",")
	req := new(logOnRequest)
	err := request.ReadEntity(&logOnRequest)
	if err != nil {

	}
	account, err := LogOn(req.uname, req.pword, host)
	if err != nil {

	}
}
