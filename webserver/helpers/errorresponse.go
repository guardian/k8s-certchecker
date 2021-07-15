package helpers

type GenericErrorResponse struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type InvalidOptionResponse struct {
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
	Options []string `json:"options"`
}
